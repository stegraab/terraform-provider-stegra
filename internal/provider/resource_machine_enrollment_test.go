package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	frameworkresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestMachineEnrollmentV0StateDropsResourceEndpoint(t *testing.T) {
	t.Parallel()
	for name, endpoint := range map[string]types.String{
		"v0.1.2 without resource endpoint": types.StringNull(),
		"v0.1.3 with resource endpoint":    types.StringValue("https://ca.example/machine-enrollment"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			upgrader, found := (&machineEnrollmentResource{}).UpgradeState(ctx)[0]
			if !found || upgrader.PriorSchema == nil {
				t.Fatal("missing version 0 state upgrader")
			}
			prior := machineEnrollmentResourceModelV0{
				ID:               types.StringValue("registration-id"),
				Endpoint:         endpoint,
				AttestorType:     types.StringValue("nutanix-vtpm"),
				AttestorIdentity: types.StringValue("bios-uuid"),
				AttestorClaims: types.MapValueMust(types.StringType, map[string]attr.Value{
					"vm_ext_id": types.StringValue("vm-id"),
				}),
				MachineIdentity: types.StringValue("host/example.internal"),
				SSHPrincipals: types.SetValueMust(types.StringType, []attr.Value{
					types.StringValue("example.internal"),
				}),
				Revoked: types.BoolValue(false),
				Status:  types.StringValue("issued"),
			}
			priorState := tfsdk.State{Schema: upgrader.PriorSchema}
			if diagnostics := priorState.Set(ctx, &prior); diagnostics.HasError() {
				t.Fatalf("set prior state: %v", diagnostics)
			}
			currentSchema := machineEnrollmentSchema()
			response := frameworkresource.UpgradeStateResponse{
				State: tfsdk.State{Schema: &currentSchema},
			}
			upgrader.StateUpgrader(ctx, frameworkresource.UpgradeStateRequest{State: &priorState}, &response)
			if response.Diagnostics.HasError() {
				t.Fatalf("upgrade state: %v", response.Diagnostics)
			}
			var upgraded machineEnrollmentResourceModel
			if diagnostics := response.State.Get(ctx, &upgraded); diagnostics.HasError() {
				t.Fatalf("read upgraded state: %v", diagnostics)
			}
			if upgraded.ID.ValueString() != prior.ID.ValueString() || upgraded.Status.ValueString() != prior.Status.ValueString() {
				t.Fatalf("upgraded state lost enrollment data: %#v", upgraded)
			}
		})
	}
}
