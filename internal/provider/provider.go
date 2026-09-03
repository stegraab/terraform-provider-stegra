package provider

import (
	"context"
	"crypto/tls"
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
	MachineEnrollmentURL   types.String `tfsdk:"machine_enrollment_url"`
	MachineEnrollmentToken types.String `tfsdk:"machine_enrollment_token"`
	StepCAURL              types.String `tfsdk:"step_ca_url"`
	StepCAAdminProvisioner types.String `tfsdk:"step_ca_admin_provisioner"`
	StepCAAdminSubject     types.String `tfsdk:"step_ca_admin_subject"`
	StepCAAdminPassword    types.String `tfsdk:"step_ca_admin_password"`
	InsecureSkipVerify     types.Bool   `tfsdk:"insecure_skip_verify"`
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
		"machine_enrollment_url": schema.StringAttribute{
			Optional:    true,
			Description: "Stegra machine-enrollment API base URL. Can also be set via STEGRA_MACHINE_ENROLLMENT_URL.",
		},
		"machine_enrollment_token": schema.StringAttribute{
			Optional:    true,
			Sensitive:   true,
			Description: "Local-development token for machine enrollment. Production uses the Step CA administrator adapter.",
		},
		"step_ca_url": schema.StringAttribute{
			Optional:    true,
			Description: "Step CA base URL used to mint short-lived production administrator credentials.",
		},
		"step_ca_admin_provisioner": schema.StringAttribute{
			Optional:    true,
			Description: "Step CA JWK provisioner used for production machine-enrollment authorization.",
		},
		"step_ca_admin_subject": schema.StringAttribute{
			Optional:    true,
			Description: "Step CA administrator subject authorized to manage machine enrollments.",
		},
		"step_ca_admin_password": schema.StringAttribute{
			Optional:    true,
			Sensitive:   true,
			Description: "Password used to decrypt the Step CA JWK provisioner private key.",
		},
		"insecure_skip_verify": schema.BoolAttribute{
			Optional:    true,
			Description: "Disable TLS verification for local development only. Production Step CA authentication rejects this setting.",
		},
	}}
}

func (p *stegraProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data stegraProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	machineEnrollmentURL, ok := configString(data.MachineEnrollmentURL, "STEGRA_MACHINE_ENROLLMENT_URL", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`machine_enrollment_url` is unknown")
		return
	}
	machineEnrollmentToken, ok := configString(data.MachineEnrollmentToken, "STEGRA_MACHINE_ENROLLMENT_TOKEN", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`machine_enrollment_token` is unknown")
		return
	}
	stepCAURL, ok := configString(data.StepCAURL, "STEGRA_STEP_CA_URL", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`step_ca_url` is unknown")
		return
	}
	adminProvisioner, ok := configString(data.StepCAAdminProvisioner, "STEGRA_STEP_CA_ADMIN_PROVISIONER", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`step_ca_admin_provisioner` is unknown")
		return
	}
	adminSubject, ok := configString(data.StepCAAdminSubject, "STEGRA_STEP_CA_ADMIN_SUBJECT", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`step_ca_admin_subject` is unknown")
		return
	}
	adminPassword, ok := configString(data.StepCAAdminPassword, "STEGRA_STEP_CA_ADMIN_PASSWORD", "")
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`step_ca_admin_password` is unknown")
		return
	}
	insecureSkipVerify, ok := configBool(data.InsecureSkipVerify, "STEGRA_INSECURE_SKIP_VERIFY", false)
	if !ok {
		resp.Diagnostics.AddError("Invalid provider configuration", "`insecure_skip_verify` is unknown")
		return
	}

	if strings.TrimSpace(machineEnrollmentURL) == "" {
		resp.Diagnostics.AddError("Missing provider configuration", "`machine_enrollment_url` must be configured")
		return
	}

	hasLocalToken := strings.TrimSpace(machineEnrollmentToken) != ""
	stepFields := []string{stepCAURL, adminProvisioner, adminSubject, adminPassword}
	hasAnyStepAuth := false
	hasAllStepAuth := true
	for _, field := range stepFields {
		configured := strings.TrimSpace(field) != ""
		hasAnyStepAuth = hasAnyStepAuth || configured
		hasAllStepAuth = hasAllStepAuth && configured
	}
	if hasLocalToken && hasAnyStepAuth {
		resp.Diagnostics.AddError("Ambiguous provider authentication", "Configure either the local machine-enrollment token or all Step CA administrator fields, not both.")
		return
	}
	if !hasLocalToken && !hasAllStepAuth {
		resp.Diagnostics.AddError("Incomplete production authentication", "Without `machine_enrollment_token`, configure `step_ca_url`, `step_ca_admin_provisioner`, `step_ca_admin_subject`, and `step_ca_admin_password`.")
		return
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecureSkipVerify}
	client := &apiClient{
		machineEnrollmentURL:   normalizeURL(machineEnrollmentURL),
		machineEnrollmentToken: strings.TrimSpace(machineEnrollmentToken),
		stepCAURL:              normalizeURL(stepCAURL),
		adminProvisioner:       strings.TrimSpace(adminProvisioner),
		adminSubject:           strings.TrimSpace(adminSubject),
		adminPassword:          adminPassword,
		insecureSkipVerify:     insecureSkipVerify,
		httpClient: &http.Client{
			Timeout:       30 * time.Second,
			Transport:     transport,
			CheckRedirect: rejectRedirects,
		},
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
