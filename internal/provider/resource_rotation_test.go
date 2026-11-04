package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	frameworkresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestParseRotationPolicyUsesUsefulDefaults(t *testing.T) {
	t.Parallel()
	policy, err := parseRotationPolicy(rotationResourceModel{
		RotationPeriod: types.StringValue("2160h"),
		RotateBefore:   types.StringNull(),
		RolloutTimeout: types.StringNull(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if policy.rotateBefore != 30*24*time.Hour {
		t.Fatalf("rotateBefore=%s", policy.rotateBefore)
	}
	if policy.rolloutTimeout != 30*24*time.Hour {
		t.Fatalf("rolloutTimeout=%s", policy.rolloutTimeout)
	}
	if policy.interval != 30*24*time.Hour {
		t.Fatalf("interval=%s, want 720h (30d)", policy.interval)
	}
}

func TestParseRotationPolicySupportsFastLocalDemo(t *testing.T) {
	t.Parallel()
	policy, err := parseRotationPolicy(rotationResourceModel{
		RotationPeriod: types.StringValue("4s"),
		RotateBefore:   types.StringNull(),
		RolloutTimeout: types.StringNull(),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := 1333333333 * time.Nanosecond
	if policy.rotateBefore != want || policy.rolloutTimeout != want || policy.interval != want {
		t.Fatalf("unexpected policy: %#v", policy)
	}
}

func TestParseRotationPolicyValidatesOverrides(t *testing.T) {
	t.Parallel()
	_, err := parseRotationPolicy(rotationResourceModel{
		RotationPeriod: types.StringValue("24h"),
		RotateBefore:   types.StringValue("6h"),
		RolloutTimeout: types.StringValue("7h"),
	})
	if err == nil {
		t.Fatal("expected rollout_timeout larger than rotate_before to fail")
	}
}

func TestParseRotationPolicyUsesConfiguredSize(t *testing.T) {
	t.Parallel()
	policy, err := parseRotationPolicy(rotationResourceModel{
		RotationPeriod: types.StringValue("4s"),
		RotateBefore:   types.StringNull(),
		RolloutTimeout: types.StringNull(),
		Size:           types.Int64Value(3),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := policy.interval, time.Second; got != want {
		t.Fatalf("interval=%s, want %s", got, want)
	}
}

func TestParseRotationPolicyRejectsSingleSlot(t *testing.T) {
	t.Parallel()
	_, err := parseRotationPolicy(rotationResourceModel{
		RotationPeriod: types.StringValue("4s"),
		RotateBefore:   types.StringNull(),
		RolloutTimeout: types.StringNull(),
		Size:           types.Int64Value(1),
	})
	if err == nil {
		t.Fatal("expected size below two to fail")
	}
}

func TestAdvanceRotationAlternatesExactlyOneSlot(t *testing.T) {
	t.Parallel()
	initialExpiry := time.Date(2026, time.December, 23, 0, 0, 0, 0, time.UTC)
	rotatedExpiry := time.Date(2027, time.February, 2, 0, 0, 0, 0, time.UTC)
	state := rotationResourceModel{
		Generation:       types.Int64Value(2),
		Size:             types.Int64Value(2),
		Slots:            initialSlots(2, expirationValue(initialExpiry)),
		ActiveSlot:       types.StringValue("0"),
		ActiveGeneration: types.Int64Value(1),
	}

	advanceRotation(&state, expirationValue(rotatedExpiry))
	if state.Generation.ValueInt64() != 3 || slotGeneration(state, "0") != 1 || slotGeneration(state, "1") != 3 {
		t.Fatalf("first rotation changed the wrong generations: %#v", state)
	}
	if state.ActiveSlot.ValueString() != "1" || state.ActiveGeneration.ValueInt64() != 3 {
		t.Fatalf("first rotation selected the wrong active credential: %#v", state)
	}
	if slotExpiresAt(state, "0") != initialExpiry.Format(time.RFC3339Nano) || slotExpiresAt(state, "1") != rotatedExpiry.Format(time.RFC3339Nano) {
		t.Fatalf("first rotation changed the wrong expirations: %#v", state)
	}

	secondExpiry := rotatedExpiry.Add(24 * time.Hour)
	advanceRotation(&state, expirationValue(secondExpiry))
	if state.Generation.ValueInt64() != 4 || slotGeneration(state, "0") != 4 || slotGeneration(state, "1") != 3 {
		t.Fatalf("second rotation changed the wrong generations: %#v", state)
	}
	if state.ActiveSlot.ValueString() != "0" || state.ActiveGeneration.ValueInt64() != 4 {
		t.Fatalf("second rotation selected the wrong active credential: %#v", state)
	}
	if slotExpiresAt(state, "0") != secondExpiry.Format(time.RFC3339Nano) || slotExpiresAt(state, "1") != rotatedExpiry.Format(time.RFC3339Nano) {
		t.Fatalf("second rotation changed the wrong expirations: %#v", state)
	}
}

func TestAdvanceRotationSupportsDynamicSize(t *testing.T) {
	t.Parallel()
	expiresAt := time.Date(2026, time.December, 23, 0, 0, 0, 0, time.UTC)
	state := rotationResourceModel{
		Generation:       types.Int64Value(3),
		Size:             types.Int64Value(3),
		Slots:            initialSlots(3, expirationValue(expiresAt)),
		ActiveSlot:       types.StringValue("0"),
		ActiveGeneration: types.Int64Value(1),
	}

	advanceRotation(&state, expirationValue(expiresAt))
	if state.ActiveSlot.ValueString() != "1" || slotGeneration(state, "0") != 1 || slotGeneration(state, "1") != 4 || slotGeneration(state, "2") != 3 {
		t.Fatalf("first three-slot rotation changed the wrong slot: %#v", state)
	}
	advanceRotation(&state, expirationValue(expiresAt))
	if state.ActiveSlot.ValueString() != "2" || slotGeneration(state, "0") != 1 || slotGeneration(state, "1") != 4 || slotGeneration(state, "2") != 5 {
		t.Fatalf("second three-slot rotation changed the wrong slot: %#v", state)
	}
	advanceRotation(&state, expirationValue(expiresAt))
	if state.ActiveSlot.ValueString() != "0" || slotGeneration(state, "0") != 6 || slotGeneration(state, "1") != 4 || slotGeneration(state, "2") != 5 {
		t.Fatalf("third three-slot rotation changed the wrong slot: %#v", state)
	}
}

func slotGeneration(model rotationResourceModel, slot string) int64 {
	return model.Slots.Elements()[slot].(types.Object).Attributes()["generation"].(types.Int64).ValueInt64()
}

func slotExpiresAt(model rotationResourceModel, slot string) string {
	return model.Slots.Elements()[slot].(types.Object).Attributes()["expires_at"].(types.String).ValueString()
}

func TestResolveUnknownExpirationsOnce(t *testing.T) {
	t.Parallel()
	resolvedAt := time.Date(2026, time.December, 23, 12, 0, 0, 0, time.UTC)
	state := rotationResourceModel{
		Generation: types.Int64Value(2),
		Size:       types.Int64Value(2),
		Slots:      initialSlots(2, types.StringUnknown()),
	}

	policy := rotationPolicy{period: 90 * 24 * time.Hour, rotateBefore: 30 * 24 * time.Hour, interval: 30 * 24 * time.Hour, size: 2}
	resolveUnknownExpirations(&state, policy, resolvedAt)
	if got, want := slotExpiresAt(state, "0"), resolvedAt.Add(policy.period).Format(time.RFC3339Nano); got != want {
		t.Fatalf("expires_at=%q, want %q", got, want)
	}
	if got, want := slotExpiresAt(state, "1"), resolvedAt.Add(60*24*time.Hour).Format(time.RFC3339Nano); got != want {
		t.Fatalf("staggered expires_at=%q, want %q", got, want)
	}

	resolveUnknownExpirations(&state, policy, resolvedAt.Add(24*time.Hour))
	if got, want := slotExpiresAt(state, "0"), resolvedAt.Add(policy.period).Format(time.RFC3339Nano); got != want {
		t.Fatalf("resolved expiration changed from %q to %q", want, got)
	}
}

func TestRotationUpdateSetsNextTimestampOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fixedNow := time.Date(2026, time.September, 24, 12, 0, 0, 0, time.UTC)
	expiresAt := fixedNow.Add(4 * time.Second)
	planModel := rotationResourceModel{
		ID:               types.StringValue("rotation-id"),
		RotationPeriod:   types.StringValue("4s"),
		RotateBefore:     types.StringValue("400ms"),
		RolloutTimeout:   types.StringValue("200ms"),
		RotationInterval: types.StringValue("1.8s"),
		Size:             types.Int64Value(2),
		Generation:       types.Int64Value(3),
		Slots: types.MapValueMust(rotationSlotType, map[string]attr.Value{
			"0": rotationSlotValue(1, expirationValue(expiresAt)),
			"1": rotationSlotValue(3, expirationValue(expiresAt)),
		}),
		ActiveSlot:       types.StringValue("1"),
		ActiveGeneration: types.Int64Value(3),
		NextRotationAt:   types.StringUnknown(),
	}
	resourceSchema := rotationSchema()
	plan := tfsdk.Plan{Schema: &resourceSchema}
	if diagnostics := plan.Set(ctx, &planModel); diagnostics.HasError() {
		t.Fatalf("set plan: %v", diagnostics)
	}
	response := frameworkresource.UpdateResponse{State: tfsdk.State{Schema: &resourceSchema}}
	prior := planModel
	prior.Generation = types.Int64Value(2)
	priorState := tfsdk.State{Schema: &resourceSchema}
	if diagnostics := priorState.Set(ctx, &prior); diagnostics.HasError() {
		t.Fatalf("set state: %v", diagnostics)
	}
	(&rotationResource{now: func() time.Time { return fixedNow }}).Update(
		ctx,
		frameworkresource.UpdateRequest{Plan: plan, State: priorState},
		&response,
	)
	if response.Diagnostics.HasError() {
		t.Fatalf("update: %v", response.Diagnostics)
	}
	var state rotationResourceModel
	if diagnostics := response.State.Get(ctx, &state); diagnostics.HasError() {
		t.Fatalf("get state: %v", diagnostics)
	}
	if got, want := state.NextRotationAt.ValueString(), fixedNow.Add(1800*time.Millisecond).Format(time.RFC3339Nano); got != want {
		t.Fatalf("next_rotation_at=%q, want %q", got, want)
	}
}

func TestPolicyChangeNeverPostponesExistingRotation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	state := rotationStateForPlanTest(now)
	state.NextRotationAt = expirationValue(now.Add(10 * 24 * time.Hour))

	config := rotationResourceModel{
		RotationPeriod:         types.StringValue("2880h"), // 120 days
		RotateBefore:           types.StringNull(),
		RolloutTimeout:         types.StringNull(),
		Size:                   types.Int64Value(2),
		AcknowledgedGeneration: types.Int64Null(),
	}
	plan := state
	plan.RotationPeriod = config.RotationPeriod
	plan.RotateBefore = types.StringUnknown()
	plan.RolloutTimeout = types.StringUnknown()
	plan.RotationInterval = types.StringUnknown()

	response := modifyRotationPlanForTest(t, now, config, plan, state)
	if response.Diagnostics.HasError() {
		t.Fatalf("modify plan: %v", response.Diagnostics)
	}
	var result rotationResourceModel
	if diagnostics := response.Plan.Get(context.Background(), &result); diagnostics.HasError() {
		t.Fatalf("get plan: %v", diagnostics)
	}
	if got, want := result.NextRotationAt.ValueString(), state.NextRotationAt.ValueString(); got != want {
		t.Fatalf("policy change postponed next_rotation_at from %q to %q", want, got)
	}
}

func TestShorterPeriodAppliesOnlyAsSlotsRotate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	state := rotationStateForPlanTest(now)
	state.RotationPeriod = types.StringValue("8760h")
	state.RotateBefore = types.StringValue("2920h0m0s")
	state.RolloutTimeout = types.StringValue("2920h0m0s")
	state.RotationInterval = types.StringValue("2920h0m0s")
	state.NextRotationAt = expirationValue(now.Add(100 * 24 * time.Hour))
	state.Slots = types.MapValueMust(rotationSlotType, map[string]attr.Value{
		"0": rotationSlotValue(1, expirationValue(now.Add(180*24*time.Hour))),
		"1": rotationSlotValue(2, expirationValue(now.Add(60*24*time.Hour))),
	})
	plan := state
	plan.RotationPeriod = types.StringValue("48h")
	plan.RotateBefore = types.StringUnknown()
	plan.RolloutTimeout = types.StringUnknown()
	plan.RotationInterval = types.StringUnknown()

	response := modifyRotationPlanForTest(t, now, plan, plan, state)
	if response.Diagnostics.HasError() {
		t.Fatalf("policy change: %v", response.Diagnostics)
	}
	var updated rotationResourceModel
	if diagnostics := response.Plan.Get(context.Background(), &updated); diagnostics.HasError() {
		t.Fatalf("get plan: %v", diagnostics)
	}
	if !updated.Slots.Equal(state.Slots) || updated.Generation.ValueInt64() != state.Generation.ValueInt64() {
		t.Fatal("policy change modified existing credential slots")
	}
	if !updated.NextRotationAt.IsUnknown() {
		t.Fatal("clock-dependent schedule should be resolved during apply")
	}
	resourceSchema := rotationSchema()
	priorState := tfsdk.State{Schema: &resourceSchema}
	if diagnostics := priorState.Set(context.Background(), &state); diagnostics.HasError() {
		t.Fatalf("set state: %v", diagnostics)
	}
	updateResponse := frameworkresource.UpdateResponse{State: tfsdk.State{Schema: &resourceSchema}}
	(&rotationResource{now: func() time.Time { return now }}).Update(context.Background(), frameworkresource.UpdateRequest{Plan: response.Plan, State: priorState}, &updateResponse)
	if updateResponse.Diagnostics.HasError() {
		t.Fatalf("apply policy: %v", updateResponse.Diagnostics)
	}
	if diagnostics := updateResponse.State.Get(context.Background(), &updated); diagnostics.HasError() {
		t.Fatalf("get updated state: %v", diagnostics)
	}
	if got, want := updated.NextRotationAt.ValueString(), expirationValue(now.Add(16*time.Hour)).ValueString(); got != want {
		t.Fatalf("next rotation = %s, want %s", got, want)
	}

	rotationTime := now.Add(16 * time.Hour)
	response = modifyRotationPlanForTest(t, rotationTime, updated, updated, updated)
	if response.Diagnostics.HasError() {
		t.Fatalf("first rotation: %v", response.Diagnostics)
	}
	var rotated rotationResourceModel
	if diagnostics := response.Plan.Get(context.Background(), &rotated); diagnostics.HasError() {
		t.Fatalf("get rotation plan: %v", diagnostics)
	}
	policy, err := parseRotationPolicy(rotated)
	if err != nil {
		t.Fatal(err)
	}
	resolveUnknownExpirations(&rotated, policy, rotationTime)
	if got, want := slotExpiresAt(rotated, "1"), expirationValue(rotationTime.Add(48*time.Hour)).ValueString(); got != want {
		t.Fatalf("rotated slot expires at %s, want %s", got, want)
	}
	if got, want := slotExpiresAt(rotated, "0"), slotExpiresAt(state, "0"); got != want {
		t.Fatalf("other slot expiry changed from %s to %s", want, got)
	}
}

func TestPolicyChangeKeepsSlotsKnownForDirectForEach(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	state := rotationStateForPlanTest(now)
	config := rotationResourceModel{
		RotationPeriod:         types.StringValue("2880h"),
		RotateBefore:           types.StringNull(),
		RolloutTimeout:         types.StringNull(),
		Size:                   types.Int64Value(2),
		AcknowledgedGeneration: types.Int64Null(),
	}
	plan := config
	plan.ID = types.StringUnknown()
	plan.RotateBefore = types.StringUnknown()
	plan.RolloutTimeout = types.StringUnknown()
	plan.RotationInterval = types.StringUnknown()
	plan.Generation = types.Int64Unknown()
	plan.Slots = types.MapUnknown(rotationSlotType)
	plan.ActiveSlot = types.StringUnknown()
	plan.ActiveGeneration = types.Int64Unknown()
	plan.RolloutPending = types.BoolUnknown()
	plan.RolloutDeadline = types.StringUnknown()
	plan.NextRotationAt = types.StringUnknown()

	response := modifyRotationPlanForTest(t, now, config, plan, state)
	if response.Diagnostics.HasError() {
		t.Fatalf("modify plan: %v", response.Diagnostics)
	}
	var result rotationResourceModel
	if diagnostics := response.Plan.Get(context.Background(), &result); diagnostics.HasError() {
		t.Fatalf("get plan: %v", diagnostics)
	}
	if result.Slots.IsUnknown() || len(result.Slots.Elements()) != 2 {
		t.Fatalf("policy update made direct for_each slots unknown: %#v", result.Slots)
	}
	if result.Generation.IsUnknown() || result.ActiveSlot.IsUnknown() {
		t.Fatalf("policy update made stable coordinator state unknown: %#v", result)
	}
}

func TestRolloutTimeoutChangeDoesNotRescheduleRotation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	state := rotationStateForPlanTest(now)
	config := rotationResourceModel{
		RotationPeriod:         types.StringValue("2160h"),
		RotateBefore:           types.StringNull(),
		RolloutTimeout:         types.StringValue("120h"),
		Size:                   types.Int64Value(2),
		AcknowledgedGeneration: types.Int64Null(),
	}
	plan := state
	plan.RolloutTimeout = config.RolloutTimeout

	response := modifyRotationPlanForTest(t, now, config, plan, state)
	if response.Diagnostics.HasError() {
		t.Fatalf("modify plan: %v", response.Diagnostics)
	}
	var result rotationResourceModel
	if diagnostics := response.Plan.Get(context.Background(), &result); diagnostics.HasError() {
		t.Fatalf("get plan: %v", diagnostics)
	}
	if got, want := result.NextRotationAt.ValueString(), state.NextRotationAt.ValueString(); got != want {
		t.Fatalf("rollout timeout change rescheduled rotation from %q to %q", want, got)
	}
}

func TestUnacknowledgedRolloutBlocksNextRotation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	state := rotationStateForPlanTest(now)
	state.Generation = types.Int64Value(3)
	state.ActiveSlot = types.StringValue("1")
	state.ActiveGeneration = types.Int64Value(3)
	state.AcknowledgedGeneration = types.Int64Value(1)
	state.RolloutPending = types.BoolValue(true)
	state.RolloutDeadline = expirationValue(now.Add(24 * time.Hour))
	state.NextRotationAt = expirationValue(now.Add(-time.Minute))
	state.Slots = types.MapValueMust(rotationSlotType, map[string]attr.Value{
		"0": rotationSlotValue(1, expirationValue(now.Add(30*24*time.Hour))),
		"1": rotationSlotValue(3, expirationValue(now.Add(90*24*time.Hour))),
	})
	config := rotationResourceModel{
		RotationPeriod:         types.StringValue("2160h"),
		RotateBefore:           types.StringNull(),
		RolloutTimeout:         types.StringNull(),
		Size:                   types.Int64Value(2),
		AcknowledgedGeneration: types.Int64Null(),
	}

	response := modifyRotationPlanForTest(t, now, config, state, state)
	if response.Diagnostics.HasError() || response.Diagnostics.WarningsCount() == 0 {
		t.Fatalf("expected a warning without blocking consumer recovery: %v", response.Diagnostics)
	}
	var result rotationResourceModel
	if diagnostics := response.Plan.Get(context.Background(), &result); diagnostics.HasError() {
		t.Fatalf("get plan: %v", diagnostics)
	}
	if result.Generation.ValueInt64() != state.Generation.ValueInt64() {
		t.Fatal("unacknowledged rollout must hold the next rotation")
	}
}

func TestRolloutTimeoutBlocksBeforeNextRotation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	state := rotationStateForPlanTest(now)
	state.Generation = types.Int64Value(3)
	state.ActiveSlot = types.StringValue("1")
	state.ActiveGeneration = types.Int64Value(3)
	state.AcknowledgedGeneration = types.Int64Value(1)
	state.RolloutPending = types.BoolValue(true)
	state.RolloutDeadline = expirationValue(now.Add(-time.Minute))
	state.NextRotationAt = expirationValue(now.Add(24 * time.Hour))
	state.Slots = types.MapValueMust(rotationSlotType, map[string]attr.Value{
		"0": rotationSlotValue(1, expirationValue(now.Add(30*24*time.Hour))),
		"1": rotationSlotValue(3, expirationValue(now.Add(90*24*time.Hour))),
	})
	config := rotationResourceModel{
		RotationPeriod:         types.StringValue("2160h"),
		RotateBefore:           types.StringNull(),
		RolloutTimeout:         types.StringNull(),
		Size:                   types.Int64Value(2),
		AcknowledgedGeneration: types.Int64Null(),
	}

	response := modifyRotationPlanForTest(t, now, config, state, state)
	if response.Diagnostics.HasError() || response.Diagnostics.WarningsCount() == 0 {
		t.Fatalf("expected an overdue warning without blocking consumer recovery: %v", response.Diagnostics)
	}
}

func TestLateAcknowledgementRecoversOverdueRollout(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	state := rotationStateForPlanTest(now)
	state.Generation = types.Int64Value(3)
	state.ActiveSlot = types.StringValue("1")
	state.ActiveGeneration = types.Int64Value(3)
	state.AcknowledgedGeneration = types.Int64Value(1)
	state.RolloutPending = types.BoolValue(true)
	state.RolloutDeadline = expirationValue(now.Add(-time.Minute))
	state.NextRotationAt = expirationValue(now.Add(24 * time.Hour))
	state.Slots = types.MapValueMust(rotationSlotType, map[string]attr.Value{
		"0": rotationSlotValue(1, expirationValue(now.Add(30*24*time.Hour))),
		"1": rotationSlotValue(3, expirationValue(now.Add(90*24*time.Hour))),
	})
	config := rotationResourceModel{
		RotationPeriod:         types.StringValue("2160h"),
		RotateBefore:           types.StringNull(),
		RolloutTimeout:         types.StringNull(),
		Size:                   types.Int64Value(2),
		AcknowledgedGeneration: types.Int64Value(3),
	}
	plan := state
	plan.AcknowledgedGeneration = types.Int64Value(3)

	response := modifyRotationPlanForTest(t, now, config, plan, state)
	if response.Diagnostics.HasError() {
		t.Fatalf("late acknowledgement should recover rollout: %v", response.Diagnostics)
	}
	var result rotationResourceModel
	if diagnostics := response.Plan.Get(context.Background(), &result); diagnostics.HasError() {
		t.Fatalf("get plan: %v", diagnostics)
	}
	if result.RolloutPending.ValueBool() || !result.RolloutDeadline.IsNull() {
		t.Fatalf("acknowledgement did not clear rollout state: %#v", result)
	}
}

func TestAcknowledgementAllowsNextRotation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	state := rotationStateForPlanTest(now)
	state.Generation = types.Int64Value(3)
	state.ActiveSlot = types.StringValue("1")
	state.ActiveGeneration = types.Int64Value(3)
	state.AcknowledgedGeneration = types.Int64Value(1)
	state.RolloutPending = types.BoolValue(true)
	state.RolloutDeadline = expirationValue(now.Add(24 * time.Hour))
	state.NextRotationAt = expirationValue(now.Add(-time.Minute))
	state.Slots = types.MapValueMust(rotationSlotType, map[string]attr.Value{
		"0": rotationSlotValue(1, expirationValue(now.Add(30*24*time.Hour))),
		"1": rotationSlotValue(3, expirationValue(now.Add(90*24*time.Hour))),
	})
	config := rotationResourceModel{
		RotationPeriod:         types.StringValue("2160h"),
		RotateBefore:           types.StringNull(),
		RolloutTimeout:         types.StringNull(),
		Size:                   types.Int64Value(2),
		AcknowledgedGeneration: types.Int64Value(3),
	}
	plan := state
	plan.AcknowledgedGeneration = types.Int64Value(3)

	response := modifyRotationPlanForTest(t, now, config, plan, state)
	if response.Diagnostics.HasError() {
		t.Fatalf("modify plan: %v", response.Diagnostics)
	}
	var result rotationResourceModel
	if diagnostics := response.Plan.Get(context.Background(), &result); diagnostics.HasError() {
		t.Fatalf("get plan: %v", diagnostics)
	}
	if result.Generation.ValueInt64() != 4 || result.ActiveSlot.ValueString() != "0" || !result.RolloutPending.ValueBool() {
		t.Fatalf("acknowledged rotation produced unexpected state: %#v", result)
	}
}

func TestMissedScheduleRotatesExactlyOneSlot(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	state := rotationStateForPlanTest(now)
	state.NextRotationAt = expirationValue(now.Add(-35 * 24 * time.Hour))
	state.Slots = types.MapValueMust(rotationSlotType, map[string]attr.Value{
		"0": rotationSlotValue(1, expirationValue(now.Add(-5*24*time.Hour))),
		"1": rotationSlotValue(2, expirationValue(now.Add(25*24*time.Hour))),
	})
	config := rotationResourceModel{
		RotationPeriod:         types.StringValue("2160h"),
		RotateBefore:           types.StringNull(),
		RolloutTimeout:         types.StringNull(),
		Size:                   types.Int64Value(2),
		AcknowledgedGeneration: types.Int64Null(),
	}

	response := modifyRotationPlanForTest(t, now, config, state, state)
	if response.Diagnostics.HasError() {
		t.Fatalf("modify plan: %v", response.Diagnostics)
	}
	if response.Diagnostics.WarningsCount() < 2 {
		t.Fatalf("expected expired-credential and missed-schedule warnings: %v", response.Diagnostics)
	}
	var result rotationResourceModel
	if diagnostics := response.Plan.Get(context.Background(), &result); diagnostics.HasError() {
		t.Fatalf("get plan: %v", diagnostics)
	}
	if result.Generation.ValueInt64() != 3 || result.ActiveGeneration.ValueInt64() != 3 {
		t.Fatalf("missed schedule must rotate exactly one slot: %#v", result)
	}
	if !result.NextRotationAt.IsUnknown() {
		t.Fatalf("next schedule must be based on successful apply time: %#v", result.NextRotationAt)
	}
}

func rotationStateForPlanTest(now time.Time) rotationResourceModel {
	return rotationResourceModel{
		ID:               types.StringValue("rotation-id"),
		RotationPeriod:   types.StringValue("2160h"),
		RotateBefore:     types.StringValue("720h0m0s"),
		RolloutTimeout:   types.StringValue("720h0m0s"),
		RotationInterval: types.StringValue("720h0m0s"),
		Size:             types.Int64Value(2),
		Generation:       types.Int64Value(2),
		Slots: types.MapValueMust(rotationSlotType, map[string]attr.Value{
			"0": rotationSlotValue(1, expirationValue(now.Add(90*24*time.Hour))),
			"1": rotationSlotValue(2, expirationValue(now.Add(60*24*time.Hour))),
		}),
		ActiveSlot:             types.StringValue("0"),
		ActiveGeneration:       types.Int64Value(1),
		AcknowledgedGeneration: types.Int64Value(1),
		RolloutPending:         types.BoolValue(false),
		RolloutDeadline:        types.StringNull(),
		NextRotationAt:         expirationValue(now.Add(30 * 24 * time.Hour)),
	}
}

func modifyRotationPlanForTest(t *testing.T, now time.Time, _ rotationResourceModel, planModel, stateModel rotationResourceModel) frameworkresource.ModifyPlanResponse {
	t.Helper()
	ctx := context.Background()
	resourceSchema := rotationSchema()
	plan := tfsdk.Plan{Schema: &resourceSchema}
	if diagnostics := plan.Set(ctx, &planModel); diagnostics.HasError() {
		t.Fatalf("set plan: %v", diagnostics)
	}
	configSDK := tfsdk.Config{Raw: plan.Raw, Schema: &resourceSchema}
	state := tfsdk.State{Schema: &resourceSchema}
	if diagnostics := state.Set(ctx, &stateModel); diagnostics.HasError() {
		t.Fatalf("set state: %v", diagnostics)
	}
	response := frameworkresource.ModifyPlanResponse{Plan: tfsdk.Plan{Schema: &resourceSchema}}
	(&rotationResource{now: func() time.Time { return now }}).ModifyPlan(
		ctx,
		frameworkresource.ModifyPlanRequest{Config: configSDK, Plan: plan, State: state},
		&response,
	)
	return response
}
