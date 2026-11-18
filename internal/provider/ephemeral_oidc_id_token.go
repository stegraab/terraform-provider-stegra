package provider

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type oidcIDTokenResource struct{}

type oidcIDTokenModel struct {
	BaseURL  types.String `tfsdk:"base_url"`
	Realm    types.String `tfsdk:"realm"`
	ClientID types.String `tfsdk:"client_id"`
	IDToken  types.String `tfsdk:"id_token"`
}

func NewOIDCIDTokenResource() ephemeral.EphemeralResource {
	return &oidcIDTokenResource{}
}

func (r *oidcIDTokenResource) Metadata(_ context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oidc_id_token"
}

func (r *oidcIDTokenResource) Schema(_ context.Context, _ ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Obtains an OIDC ID token using the local Stegra CLI.",
		Attributes: map[string]schema.Attribute{
			"base_url":  schema.StringAttribute{Required: true, Description: "HTTPS base URL of the identity provider."},
			"realm":     schema.StringAttribute{Required: true, Description: "OIDC realm name."},
			"client_id": schema.StringAttribute{Required: true, Description: "Public OIDC client ID."},
			"id_token":  schema.StringAttribute{Computed: true, Sensitive: true, Description: "OIDC ID token returned by the CLI."},
		},
	}
}

func (r *oidcIDTokenResource) Open(ctx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var data oidcIDTokenModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if os.Getenv("GITLAB_CI") == "true" {
		resp.Diagnostics.AddError("Interactive OIDC authentication is unavailable in CI",
			"Configure the pipeline to supply its own credential.")
		return
	}

	baseURL := data.BaseURL.ValueString()
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		resp.Diagnostics.AddError("Invalid OIDC base URL", "Set base_url to an HTTPS URL without credentials, a query, or a fragment.")
		return
	}
	if strings.TrimSpace(data.Realm.ValueString()) == "" || strings.TrimSpace(data.ClientID.ValueString()) == "" {
		resp.Diagnostics.AddError("Invalid OIDC client configuration", "Set realm and client_id to nonempty values.")
		return
	}

	output, err := commandOutput(ctx, "stegra", "auth", "stegra", "--base-url", baseURL,
		"--realm", data.Realm.ValueString(), "--client-id", data.ClientID.ValueString(), "--token-only")
	if err != nil {
		resp.Diagnostics.AddError("Stegra SSO failed",
			"Check that the Stegra CLI is installed on PATH and that you can reach the identity provider.")
		return
	}

	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(output, &tokens); err != nil || strings.TrimSpace(tokens.IDToken) == "" {
		resp.Diagnostics.AddError("Stegra SSO returned no usable ID token",
			"Check that the OIDC client supports interactive login and returns an ID token.")
		return
	}

	data.IDToken = types.StringValue(tokens.IDToken)
	resp.Diagnostics.Append(resp.Result.Set(ctx, &data)...)
}
