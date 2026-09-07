package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = &machineEnrollmentResource{}
	_ resource.ResourceWithConfigure = &machineEnrollmentResource{}
)

type machineEnrollmentResource struct {
	client *apiClient
}

type machineEnrollmentResourceModel struct {
	ID               types.String `tfsdk:"id"`
	Endpoint         types.String `tfsdk:"endpoint"`
	AttestorType     types.String `tfsdk:"attestor_type"`
	AttestorIdentity types.String `tfsdk:"attestor_identity"`
	AttestorClaims   types.Map    `tfsdk:"attestor_claims"`
	MachineIdentity  types.String `tfsdk:"machine_identity"`
	SSHPrincipals    types.Set    `tfsdk:"ssh_principals"`
	Revoked          types.Bool   `tfsdk:"revoked"`
	Status           types.String `tfsdk:"status"`
}

func NewMachineEnrollmentResource() resource.Resource {
	return &machineEnrollmentResource{}
}

func (r *machineEnrollmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_machine_enrollment"
}

func (r *machineEnrollmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Attributes: map[string]schema.Attribute{
		"id": schema.StringAttribute{Computed: true},
		"endpoint": schema.StringAttribute{
			Required:    true,
			Description: "Stegra machine-enrollment API base URL.",
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIf(
				func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
					// Provider versions before v0.1.3 stored the endpoint only in
					// provider configuration. Adopt it into legacy resource state
					// without revoking and recreating existing enrollments.
					resp.RequiresReplace = shouldReplaceMachineEnrollmentEndpoint(req.StateValue)
				},
				"Changing an endpoint already recorded in state replaces the enrollment; adding it to legacy state does not.",
				"Changing an endpoint already recorded in state replaces the enrollment; adding it to legacy state does not.",
			)},
		},
		"attestor_type": schema.StringAttribute{
			Required:      true,
			Description:   "Platform attestor type, for example nutanix-vtpm.",
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"attestor_identity": schema.StringAttribute{
			Required:      true,
			Description:   "Stable identity observable by the attesting machine, such as a VM BIOS UUID.",
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"attestor_claims": schema.MapAttribute{
			Required:      true,
			ElementType:   types.StringType,
			Description:   "Expected platform claims verified by the selected attestor implementation.",
			PlanModifiers: []planmodifier.Map{mapplanmodifier.RequiresReplace()},
		},
		"machine_identity": schema.StringAttribute{
			Required:      true,
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"ssh_principals": schema.SetAttribute{
			Required:      true,
			ElementType:   types.StringType,
			PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()},
		},
		"revoked": schema.BoolAttribute{
			Optional:    true,
			Computed:    true,
			Default:     booldefault.StaticBool(false),
			Description: "One-way emergency switch that revokes this enrollment. Recovery requires explicitly replacing the resource.",
		},
		"status": schema.StringAttribute{Computed: true},
	}}
}

func shouldReplaceMachineEnrollmentEndpoint(stateValue types.String) bool {
	return !stateValue.IsNull() && !stateValue.IsUnknown()
}

func (r *machineEnrollmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*apiClient)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type", fmt.Sprintf("Expected *apiClient, got: %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *machineEnrollmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan machineEnrollmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Revoked.ValueBool() {
		resp.Diagnostics.AddError(
			"Cannot create a revoked machine enrollment",
			"Set revoked to false to create the enrollment. Keep a revoked resource in state, and use explicit resource replacement only after the incident has been investigated.",
		)
		return
	}
	input, ok := expandMachineEnrollment(ctx, plan, resp)
	if !ok {
		return
	}
	client, err := r.clientFor(plan.Endpoint.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid machine enrollment endpoint", err.Error())
		return
	}
	created, err := client.createMachineEnrollment(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create machine enrollment", err.Error())
		return
	}
	resp.Diagnostics.Append(setMachineEnrollmentState(ctx, &plan, created)...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *machineEnrollmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state machineEnrollmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.Endpoint.IsNull() || state.Endpoint.IsUnknown() {
		// Legacy state cannot recover the former provider-level endpoint.
		// Preserve it until Update adopts the endpoint from configuration.
		return
	}
	client, err := r.clientFor(state.Endpoint.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid machine enrollment endpoint", err.Error())
		return
	}
	registration, found, err := client.getMachineEnrollment(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read machine enrollment", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	if isInactiveMachineEnrollmentStatus(registration.Status) {
		resp.Diagnostics.AddWarning(
			"Machine enrollment is inactive",
			fmt.Sprintf("Registration %s has status %q. Review the cause and explicitly replace this resource to create another registration.", registration.ID, registration.Status),
		)
	}
	resp.Diagnostics.Append(setMachineEnrollmentState(ctx, &state, registration)...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}
}

func isInactiveMachineEnrollmentStatus(status string) bool {
	return status == "expired" || status == "revoked"
}

func (r *machineEnrollmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state machineEnrollmentResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := validateMachineEnrollmentRevocation(state.Revoked.ValueBool(), plan.Revoked.ValueBool()); err != nil {
		resp.Diagnostics.AddError("Invalid machine enrollment revocation change", err.Error())
		return
	}
	legacyEndpointMigration := state.Endpoint.IsNull() || state.Endpoint.IsUnknown()
	if legacyEndpointMigration && !plan.Revoked.ValueBool() {
		client, err := r.clientFor(plan.Endpoint.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Invalid machine enrollment endpoint", err.Error())
			return
		}
		registration, found, err := client.getMachineEnrollment(ctx, state.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Failed to read machine enrollment", err.Error())
			return
		}
		if !found {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(setMachineEnrollmentState(ctx, &plan, registration)...)
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		}
		return
	}
	if !plan.Revoked.ValueBool() {
		resp.Diagnostics.AddError("Machine enrollment update is unsupported", "All configurable attributes except revoked require replacement.")
		return
	}
	client, err := r.clientFor(plan.Endpoint.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid machine enrollment endpoint", err.Error())
		return
	}
	if err := client.revokeMachineEnrollment(ctx, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to revoke machine enrollment", err.Error())
		return
	}
	registration, found, err := client.getMachineEnrollment(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read revoked machine enrollment", err.Error())
		return
	}
	if !found {
		resp.Diagnostics.AddError("Revoked machine enrollment disappeared", "The enrollment API did not retain the revoked registration audit record.")
		return
	}
	resp.Diagnostics.Append(setMachineEnrollmentState(ctx, &plan, registration)...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func validateMachineEnrollmentRevocation(current, planned bool) error {
	if current && !planned {
		return fmt.Errorf("revocation cannot be reversed in place; remove revoked = true and explicitly replace the resource after investigating the incident")
	}
	return nil
}

func (r *machineEnrollmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state machineEnrollmentResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	client, err := r.clientFor(state.Endpoint.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid machine enrollment endpoint", err.Error())
		return
	}
	if err := client.revokeMachineEnrollment(ctx, state.ID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Failed to revoke machine enrollment", err.Error())
	}
}

func (r *machineEnrollmentResource) clientFor(endpoint string) (*apiClient, error) {
	client := *r.client
	client.machineEnrollmentURL = normalizeURL(endpoint)
	if err := client.validateTransport(); err != nil {
		return nil, err
	}
	return &client, nil
}

func expandMachineEnrollment(ctx context.Context, plan machineEnrollmentResourceModel, resp *resource.CreateResponse) (machineEnrollment, bool) {
	claims := make(map[string]string)
	resp.Diagnostics.Append(plan.AttestorClaims.ElementsAs(ctx, &claims, false)...)
	principals := make([]string, 0)
	resp.Diagnostics.Append(plan.SSHPrincipals.ElementsAs(ctx, &principals, false)...)
	if resp.Diagnostics.HasError() {
		return machineEnrollment{}, false
	}
	return machineEnrollment{
		AttestorType: plan.AttestorType.ValueString(), AttestorIdentity: plan.AttestorIdentity.ValueString(),
		AttestorClaims: claims, MachineIdentity: plan.MachineIdentity.ValueString(), SSHPrincipals: principals,
	}, true
}

func setMachineEnrollmentState(ctx context.Context, state *machineEnrollmentResourceModel, registration machineEnrollment) []diag.Diagnostic {
	var diagnostics diag.Diagnostics
	state.ID = types.StringValue(registration.ID)
	state.AttestorType = types.StringValue(registration.AttestorType)
	state.AttestorIdentity = types.StringValue(registration.AttestorIdentity)
	state.MachineIdentity = types.StringValue(registration.MachineIdentity)
	state.Revoked = types.BoolValue(registration.Status == "revoked")
	state.Status = types.StringValue(registration.Status)
	claims, claimDiagnostics := types.MapValueFrom(ctx, types.StringType, registration.AttestorClaims)
	diagnostics.Append(claimDiagnostics...)
	state.AttestorClaims = claims
	principals, principalDiagnostics := types.SetValueFrom(ctx, types.StringType, registration.SSHPrincipals)
	diagnostics.Append(principalDiagnostics...)
	state.SSHPrincipals = principals
	return diagnostics
}
