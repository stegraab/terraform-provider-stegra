package provider

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &stegraProvider{}

type stegraProvider struct {
	version string
}

type stegraProviderModel struct {
	MachineEnrollmentEndpoint types.String `tfsdk:"machine_enrollment_endpoint"`
	MachineEnrollmentToken    types.String `tfsdk:"machine_enrollment_token"`
	MachineEnrollmentAuthURL  types.String `tfsdk:"machine_enrollment_auth_url"`
	InsecureSkipVerify        types.Bool   `tfsdk:"insecure_skip_verify"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &stegraProvider{version: version}
	}
}

func (p *stegraProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "stegra"
	resp.Version = p.version
}

func (p *stegraProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{Attributes: map[string]schema.Attribute{
		"machine_enrollment_endpoint": schema.StringAttribute{
			Required:    true,
			Description: "Shared Stegra machine-enrollment API base URL for resources managed by this provider.",
		},
		"machine_enrollment_token": schema.StringAttribute{
			Optional:    true,
			Sensitive:   true,
			Description: "Static machine-enrollment token for local development only. Production obtains a short-lived token with the Stegra CLI.",
		},
		"machine_enrollment_auth_url": schema.StringAttribute{
			Optional:    true,
			Description: "Stegra identity-provider base URL used by `stegra auth stegra` for production machine-enrollment authentication.",
		},
		"insecure_skip_verify": schema.BoolAttribute{
			Optional:    true,
			Description: "Disable TLS verification for local development only. Production OIDC authentication rejects this setting.",
		},
	}}
}

func (p *stegraProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data stegraProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	machineEnrollmentEndpoint, ok := configString(data.MachineEnrollmentEndpoint, "STEGRA_MACHINE_ENROLLMENT_ENDPOINT", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`machine_enrollment_endpoint` is unknown")
		return
	}
	machineEnrollmentToken, ok := configString(data.MachineEnrollmentToken, "STEGRA_MACHINE_ENROLLMENT_TOKEN", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`machine_enrollment_token` is unknown")
		return
	}
	machineEnrollmentAuthURL, ok := configString(data.MachineEnrollmentAuthURL, "STEGRA_MACHINE_ENROLLMENT_AUTH_URL", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`machine_enrollment_auth_url` is unknown")
		return
	}
	insecureSkipVerify, ok := configBool(data.InsecureSkipVerify, "STEGRA_INSECURE_SKIP_VERIFY", false)
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`insecure_skip_verify` is unknown")
		return
	}
	if strings.TrimSpace(machineEnrollmentEndpoint) == "" {
		resp.Diagnostics.AddError("Missing provider configuration", "`machine_enrollment_endpoint` must be configured")
		return
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureSkipVerify}
	client := &apiClient{
		machineEnrollmentURL: normalizeURL(machineEnrollmentEndpoint),
		insecureSkipVerify:   insecureSkipVerify,
		httpClient: &http.Client{
			Timeout:       30 * time.Second,
			Transport:     transport,
			CheckRedirect: rejectRedirects,
		},
	}
	if strings.TrimSpace(machineEnrollmentToken) != "" {
		client.tokenSource = staticTokenSource(strings.TrimSpace(machineEnrollmentToken))
	} else {
		username, password, configured, err := keycloakPasswordCredentials()
		if err != nil {
			resp.Diagnostics.AddError("Invalid pipeline authentication", err.Error())
			return
		}
		if configured {
			client.tokenSource = &keycloakPasswordTokenSource{
				authURL:    normalizeURL(machineEnrollmentAuthURL),
				username:   username,
				password:   password,
				httpClient: client.httpClient,
			}
		} else {
			client.tokenSource = &stegraCLITokenSource{authURL: normalizeURL(machineEnrollmentAuthURL)}
		}
	}
	if err := client.validateTransport(); err != nil {
		resp.Diagnostics.AddError("Invalid provider transport", err.Error())
		return
	}
	resp.ResourceData = client
}

func keycloakPasswordCredentials() (string, string, bool, error) {
	username, usernameConfigured := os.LookupEnv("KEYCLOAK_USER")
	password, passwordConfigured := os.LookupEnv("KEYCLOAK_PASSWORD")
	if usernameConfigured != passwordConfigured {
		return "", "", false, errors.New("KEYCLOAK_USER and KEYCLOAK_PASSWORD must be configured together")
	}
	if !usernameConfigured {
		return "", "", false, nil
	}
	if strings.TrimSpace(username) == "" || password == "" {
		return "", "", false, errors.New("KEYCLOAK_USER and KEYCLOAK_PASSWORD must not be empty")
	}
	return strings.TrimSpace(username), password, true, nil
}

func (p *stegraProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewMachineEnrollmentResource}
}

func (p *stegraProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func normalizeURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func rejectRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func configString(value types.String, environmentVariable string, defaultValue string) (string, bool) {
	if value.IsUnknown() {
		return "", false
	}
	if !value.IsNull() && value.ValueString() != "" {
		return value.ValueString(), true
	}
	if environmentValue, found := os.LookupEnv(environmentVariable); found && environmentValue != "" {
		return environmentValue, true
	}
	return defaultValue, true
}

func configBool(value types.Bool, environmentVariable string, defaultValue bool) (bool, bool) {
	if value.IsUnknown() {
		return false, false
	}
	if !value.IsNull() {
		return value.ValueBool(), true
	}
	if environmentValue, found := os.LookupEnv(environmentVariable); found && environmentValue != "" {
		parsed, err := strconv.ParseBool(environmentValue)
		if err == nil {
			return parsed, true
		}
	}
	return defaultValue, true
}
