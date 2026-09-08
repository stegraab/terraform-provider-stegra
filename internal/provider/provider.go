package provider

import (
	"context"
	"crypto/tls"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
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
			Description: "Static machine-enrollment token for local development only. Production uses ambient AWS credentials.",
		},
		"insecure_skip_verify": schema.BoolAttribute{
			Optional:    true,
			Description: "Disable TLS verification for local development only. Production AWS IAM authentication rejects this setting.",
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
		machineEnrollmentURL:   normalizeURL(machineEnrollmentEndpoint),
		machineEnrollmentToken: strings.TrimSpace(machineEnrollmentToken),
		insecureSkipVerify:     insecureSkipVerify,
		httpClient: &http.Client{
			Timeout:       30 * time.Second,
			Transport:     transport,
			CheckRedirect: rejectRedirects,
		},
	}
	if client.machineEnrollmentToken == "" {
		awsConfig, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Failed to load AWS configuration", "Production machine enrollment uses ambient AWS credentials: "+err.Error())
			return
		}
		if strings.TrimSpace(awsConfig.Region) == "" {
			resp.Diagnostics.AddError("Missing AWS region", "Production machine enrollment requires a region in the standard AWS configuration chain, for example AWS_REGION or the active AWS profile.")
			return
		}
		client.awsRegion = awsConfig.Region
		client.awsCredentials = awsConfig.Credentials
	}
	if err := client.validateTransport(); err != nil {
		resp.Diagnostics.AddError("Invalid provider transport", err.Error())
		return
	}
	resp.ResourceData = client
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
