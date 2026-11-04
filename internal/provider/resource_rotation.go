package provider

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &rotationResource{}
	_ resource.ResourceWithModifyPlan     = &rotationResource{}
	_ resource.ResourceWithValidateConfig = &rotationResource{}
)

type rotationResource struct {
	now func() time.Time
}

type rotationResourceModel struct {
	ID                     types.String `tfsdk:"id"`
	RotationPeriod         types.String `tfsdk:"rotation_period"`
	RotateBefore           types.String `tfsdk:"rotate_before"`
	RolloutTimeout         types.String `tfsdk:"rollout_timeout"`
	RotationInterval       types.String `tfsdk:"rotation_interval"`
	Size                   types.Int64  `tfsdk:"size"`
	Generation             types.Int64  `tfsdk:"generation"`
	Slots                  types.Map    `tfsdk:"slots"`
	ActiveSlot             types.String `tfsdk:"active_slot"`
	ActiveGeneration       types.Int64  `tfsdk:"active_generation"`
	AcknowledgedGeneration types.Int64  `tfsdk:"acknowledged_generation"`
	RolloutPending         types.Bool   `tfsdk:"rollout_pending"`
	RolloutDeadline        types.String `tfsdk:"rollout_deadline"`
	NextRotationAt         types.String `tfsdk:"next_rotation_at"`
}

type rotationPolicy struct {
	period         time.Duration
	rotateBefore   time.Duration
	rolloutTimeout time.Duration
	interval       time.Duration
	size           int64
}

var rotationSlotAttributeTypes = map[string]attr.Type{
	"generation": types.Int64Type,
	"expires_at": types.StringType,
}

var rotationSlotType = types.ObjectType{AttrTypes: rotationSlotAttributeTypes}

func NewRotationResource() resource.Resource {
	return &rotationResource{now: time.Now}
}

func (r *rotationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rotation"
}

func (r *rotationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rotationSchema()
}

func rotationSchema() schema.Schema {
	return schema.Schema{
		Description: "Coordinates multi-slot credential rotation using numeric generations. It never stores secret material.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Stable opaque rotation identifier.",
			},
			"rotation_period": schema.StringAttribute{
				Required:    true,
				Description: "Maximum intended age of one credential as a Go duration, for example 2160h for 90 days.",
			},
			"rotate_before": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Safety window before expiration. Defaults to rotation_period / (size + 1), producing an evenly staggered schedule.",
			},
			"rollout_timeout": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Maximum rollout window. Defaults to the shorter of rotate_before and rotation_interval.",
			},
			"rotation_interval": schema.StringAttribute{
				Computed:    true,
				Description: "Derived interval between slot rotations: (rotation_period - rotate_before) / size.",
			},
			"size": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(2),
				Description: "Number of independently valid credential slots. Defaults to 2. Changing size replaces the rotation coordinator.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"generation": schema.Int64Attribute{
				Computed:    true,
				Description: "Monotonically increasing global rotation event counter. Use each slot's generation for *_wo_version arguments.",
			},
			"slots": schema.MapNestedAttribute{
				Computed:    true,
				Description: "Iterable map of stable slot generations and requested expiration timestamps, suitable for direct use with for_each.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"generation": schema.Int64Attribute{
							Computed:    true,
							Description: "Generation of this credential slot.",
						},
						"expires_at": schema.StringAttribute{
							Computed:    true,
							Description: "Stable RFC3339 expiration requested from the downstream credential resource for this slot generation.",
						},
					},
				},
			},
			"active_slot": schema.StringAttribute{
				Computed:    true,
				Description: "Preferred zero-based slot key. Every entry in slots is expected to remain valid.",
			},
			"active_generation": schema.Int64Attribute{
				Computed:    true,
				Description: "Generation of active_slot. Suitable for a consumer's *_wo_version argument.",
			},
			"acknowledged_generation": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Latest preferred generation confirmed as rolled out to consumers. The next rotation is blocked until this reaches active_generation.",
			},
			"rollout_pending": schema.BoolAttribute{
				Computed:    true,
				Description: "True while active_generation has not been acknowledged.",
			},
			"rollout_deadline": schema.StringAttribute{
				Computed:    true,
				Description: "RFC3339 deadline for acknowledging the current preferred generation, or null when no rollout is pending.",
			},
			"next_rotation_at": schema.StringAttribute{
				Computed:    true,
				Description: "Next planned one-slot rotation in RFC3339 format.",
			},
		},
	}
}

func (r *rotationResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config rotationResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.RotationPeriod.IsUnknown() {
		return
	}
	_, err := parseRotationPolicy(config)
	if err != nil {
		resp.Diagnostics.AddError("Invalid rotation policy", err.Error())
	}
}

func (r *rotationResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var config, plan rotationResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || config.RotationPeriod.IsUnknown() {
		return
	}

	policy, err := parseRotationPolicy(config)
	if err != nil {
		resp.Diagnostics.AddError("Invalid rotation policy", err.Error())
		return
	}
	applyPolicyToModel(&plan, policy)
	now := r.clock().UTC()

	if req.State.Raw.IsNull() {
		if !config.AcknowledgedGeneration.IsNull() && !config.AcknowledgedGeneration.IsUnknown() && config.AcknowledgedGeneration.ValueInt64() != 1 {
			resp.Diagnostics.AddError("Invalid initial acknowledgement", "acknowledged_generation must be omitted or set to 1 when creating a rotation.")
			return
		}
		initializeRotation(&plan, policy.size, types.StringUnknown())
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}

	var state rotationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Size.ValueInt64() != state.Size.ValueInt64() {
		if !config.AcknowledgedGeneration.IsNull() && !config.AcknowledgedGeneration.IsUnknown() && config.AcknowledgedGeneration.ValueInt64() != 1 {
			resp.Diagnostics.AddError("Invalid replacement acknowledgement", "Reset acknowledged_generation to 1 when replacing the coordinator by changing size.")
			return
		}
		initializeRotation(&plan, policy.size, types.StringUnknown())
		plan.NextRotationAt = types.StringUnknown()
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}

	// Preserve a transition Terraform has already carried into this call.
	if rotationPlanAlreadyModified(plan, state) {
		return
	}

	// Terraform marks computed attributes unknown when any configured value
	// changes. Keep the established slot map and coordinator state known unless
	// this plan actually performs a rotation. In particular, consumers must be
	// able to use slots directly as a for_each map during policy-only updates.
	plannedAcknowledgement := plan.AcknowledgedGeneration
	plan.ID = state.ID
	plan.Generation = state.Generation
	plan.Slots = state.Slots
	plan.ActiveSlot = state.ActiveSlot
	plan.ActiveGeneration = state.ActiveGeneration
	plan.AcknowledgedGeneration = plannedAcknowledgement
	plan.RolloutPending = state.RolloutPending
	plan.RolloutDeadline = state.RolloutDeadline
	plan.NextRotationAt = state.NextRotationAt

	if plan.AcknowledgedGeneration.IsNull() || plan.AcknowledgedGeneration.IsUnknown() {
		plan.AcknowledgedGeneration = state.AcknowledgedGeneration
	}
	acknowledged := plan.AcknowledgedGeneration.ValueInt64()
	if acknowledged < state.AcknowledgedGeneration.ValueInt64() {
		resp.Diagnostics.AddError(
			"Invalid rollout acknowledgement",
			"acknowledged_generation cannot move backwards.",
		)
		return
	}
	if acknowledged > state.ActiveGeneration.ValueInt64() {
		resp.Diagnostics.AddError(
			"Invalid rollout acknowledgement",
			fmt.Sprintf("acknowledged_generation cannot exceed the current active_generation (%d).", state.ActiveGeneration.ValueInt64()),
		)
		return
	}

	rolloutPending := acknowledged < state.ActiveGeneration.ValueInt64()
	plan.RolloutPending = types.BoolValue(rolloutPending)
	if !rolloutPending {
		plan.RolloutDeadline = types.StringNull()
	} else if !state.RolloutDeadline.IsNull() && !state.RolloutDeadline.IsUnknown() {
		deadline, deadlineErr := time.Parse(time.RFC3339Nano, state.RolloutDeadline.ValueString())
		if deadlineErr != nil {
			resp.Diagnostics.AddError("Invalid rotation state", fmt.Sprintf("rollout_deadline is invalid: %v", deadlineErr))
			return
		}
		if !now.Before(deadline) {
			resp.Diagnostics.AddWarning(
				"Credential rollout acknowledgement overdue",
				fmt.Sprintf("Generation %d was not acknowledged before %s. Retry any failed consumer changes and set acknowledged_generation after consumers have switched; no further credential will rotate until then.", state.ActiveGeneration.ValueInt64(), deadline.Format(time.RFC3339)),
			)
		}
	}

	next, parseErr := time.Parse(time.RFC3339Nano, state.NextRotationAt.ValueString())
	if parseErr != nil {
		resp.Diagnostics.AddError("Invalid rotation state", fmt.Sprintf("next_rotation_at is invalid: %v", parseErr))
		return
	}
	previousNext := next

	policyChanged := plan.RotationPeriod.ValueString() != state.RotationPeriod.ValueString() ||
		plan.RotateBefore.ValueString() != state.RotateBefore.ValueString()
	if policyChanged {
		next = minTime(next, now.Add(policy.interval))
		earliestExpiry, expiryErr := earliestRequestedExpiration(state)
		if expiryErr != nil {
			resp.Diagnostics.AddError("Invalid rotation state", expiryErr.Error())
			return
		}
		next = minTime(next, earliestExpiry.Add(-policy.rotateBefore))
	}
	plan.NextRotationAt = types.StringValue(next.Format(time.RFC3339Nano))
	if policyChanged && now.Before(next) && next.Before(previousNext) {
		// Resolve clock-dependent schedule changes at apply time: Terraform may
		// request plan expansion with a fresh clock after the initial plan.
		plan.NextRotationAt = types.StringUnknown()
	}

	expiredSlots, expiryErr := countExpiredSlots(state, now)
	if expiryErr != nil {
		resp.Diagnostics.AddError("Invalid rotation state", expiryErr.Error())
		return
	}
	if expiredSlots > 0 {
		resp.Diagnostics.AddWarning(
			"Credential rotation is overdue",
			fmt.Sprintf("%d credential slot(s) have passed their requested expiration. This apply will still rotate at most one slot so credentials are never replaced back-to-back.", expiredSlots),
		)
	}
	if delay := now.Sub(next); delay >= policy.interval {
		resp.Diagnostics.AddWarning(
			"Credential rotation schedule was missed",
			fmt.Sprintf("Rotation is overdue by %s. This apply will advance only one slot and schedule the following rotation from the successful apply time.", delay.Round(time.Second)),
		)
	}

	if !now.Before(next) {
		if rolloutPending {
			resp.Diagnostics.AddWarning(
				"Credential rollout not acknowledged",
				fmt.Sprintf("Generation %d is still pending acknowledgement. The next rotation is held until consumers have switched and acknowledged_generation is set.", state.ActiveGeneration.ValueInt64()),
			)
			resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
			return
		}
		advanceRotation(&plan, types.StringUnknown())
		// Never catch up multiple missed intervals in one apply. Starting from
		// now prevents both credential slots from rotating back-to-back.
		plan.NextRotationAt = types.StringUnknown()
	}

	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

func (r *rotationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan rotationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	policy, err := parseRotationPolicy(plan)
	if err != nil {
		resp.Diagnostics.AddError("Invalid rotation policy", err.Error())
		return
	}
	id, err := uuid.GenerateUUID()
	if err != nil {
		resp.Diagnostics.AddError("Failed to create rotation identifier", err.Error())
		return
	}
	applyPolicyToModel(&plan, policy)
	plan.ID = types.StringValue(id)
	if plan.Slots.IsNull() || plan.Slots.IsUnknown() {
		initializeRotation(&plan, policy.size, types.StringUnknown())
	}
	resolveUnknownExpirations(&plan, policy, r.clock().UTC())
	if plan.AcknowledgedGeneration.IsNull() || plan.AcknowledgedGeneration.IsUnknown() {
		plan.AcknowledgedGeneration = plan.ActiveGeneration
	}
	plan.RolloutPending = types.BoolValue(false)
	plan.RolloutDeadline = types.StringNull()
	plan.NextRotationAt = types.StringValue(r.clock().UTC().Add(policy.interval).Format(time.RFC3339Nano))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *rotationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state rotationResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}
}

func (r *rotationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state rotationResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.NextRotationAt.IsUnknown() {
		policy, err := parseRotationPolicy(plan)
		if err != nil {
			resp.Diagnostics.AddError("Invalid rotation policy", err.Error())
			return
		}
		now := r.clock().UTC()
		next := now.Add(policy.interval)
		if plan.Generation.ValueInt64() == state.Generation.ValueInt64() {
			previous, parseErr := time.Parse(time.RFC3339Nano, state.NextRotationAt.ValueString())
			expiry, expiryErr := earliestRequestedExpiration(state)
			if parseErr != nil || expiryErr != nil {
				resp.Diagnostics.AddError("Invalid rotation state", "Cannot reschedule rotation because its existing timestamp or expiration is invalid.")
				return
			}
			next = minTime(next, minTime(previous, expiry.Add(-policy.rotateBefore)))
		} else {
			resolveUnknownExpirations(&plan, policy, now)
			plan.RolloutDeadline = types.StringValue(now.Add(policy.rolloutTimeout).Format(time.RFC3339Nano))
		}
		plan.NextRotationAt = expirationValue(next)
	}
	plan.RolloutPending = types.BoolValue(plan.AcknowledgedGeneration.ValueInt64() < plan.ActiveGeneration.ValueInt64())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *rotationResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}

func (r *rotationResource) clock() time.Time {
	if r.now == nil {
		return time.Now()
	}
	return r.now()
}

func parseRotationPolicy(model rotationResourceModel) (rotationPolicy, error) {
	period, err := time.ParseDuration(model.RotationPeriod.ValueString())
	if err != nil || period <= 0 {
		return rotationPolicy{}, fmt.Errorf("rotation_period must be a positive Go duration: %q", model.RotationPeriod.ValueString())
	}

	size := model.Size.ValueInt64()
	if model.Size.IsNull() || model.Size.IsUnknown() {
		size = 2
	}
	if size < 2 {
		return rotationPolicy{}, fmt.Errorf("size must be at least 2, got %d", size)
	}

	rotateBefore := period / time.Duration(size+1)
	if !model.RotateBefore.IsNull() && !model.RotateBefore.IsUnknown() {
		rotateBefore, err = time.ParseDuration(model.RotateBefore.ValueString())
		if err != nil || rotateBefore <= 0 {
			return rotationPolicy{}, fmt.Errorf("rotate_before must be a positive Go duration: %q", model.RotateBefore.ValueString())
		}
	}
	if rotateBefore >= period {
		return rotationPolicy{}, fmt.Errorf("rotate_before (%s) must be shorter than rotation_period (%s)", rotateBefore, period)
	}

	interval := (period - rotateBefore) / time.Duration(size)
	if interval <= 0 {
		return rotationPolicy{}, fmt.Errorf("derived rotation interval must be positive")
	}

	rolloutWindow := min(rotateBefore, interval)
	rolloutTimeout := rolloutWindow
	if !model.RolloutTimeout.IsNull() && !model.RolloutTimeout.IsUnknown() {
		rolloutTimeout, err = time.ParseDuration(model.RolloutTimeout.ValueString())
		if err != nil || rolloutTimeout <= 0 {
			return rotationPolicy{}, fmt.Errorf("rollout_timeout must be a positive Go duration: %q", model.RolloutTimeout.ValueString())
		}
	}
	if rolloutTimeout > rolloutWindow {
		return rotationPolicy{}, fmt.Errorf("rollout_timeout (%s) must not exceed the available rollout window (%s)", rolloutTimeout, rolloutWindow)
	}
	return rotationPolicy{period: period, rotateBefore: rotateBefore, rolloutTimeout: rolloutTimeout, interval: interval, size: size}, nil
}

func applyPolicyToModel(model *rotationResourceModel, policy rotationPolicy) {
	model.RotateBefore = types.StringValue(policy.rotateBefore.String())
	model.RolloutTimeout = types.StringValue(policy.rolloutTimeout.String())
	model.RotationInterval = types.StringValue(policy.interval.String())
}

func advanceRotation(model *rotationResourceModel, expiresAt types.String) {
	nextGeneration := model.Generation.ValueInt64() + 1
	nextSlot := strconv.FormatInt(nextGeneration%model.Size.ValueInt64(), 10)
	elements := make(map[string]attr.Value, len(model.Slots.Elements()))
	for key, value := range model.Slots.Elements() {
		elements[key] = value
	}
	elements[nextSlot] = rotationSlotValue(nextGeneration, expiresAt)

	model.Generation = types.Int64Value(nextGeneration)
	model.Slots = types.MapValueMust(rotationSlotType, elements)
	model.ActiveSlot = types.StringValue(nextSlot)
	model.ActiveGeneration = types.Int64Value(nextGeneration)
	model.RolloutPending = types.BoolValue(true)
	model.RolloutDeadline = types.StringUnknown()
}

func initialSlots(size int64, expiresAt types.String) types.Map {
	elements := make(map[string]attr.Value, size)
	for slot := int64(0); slot < size; slot++ {
		elements[strconv.FormatInt(slot, 10)] = rotationSlotValue(slot+1, expiresAt)
	}
	return types.MapValueMust(rotationSlotType, elements)
}

func initializeRotation(model *rotationResourceModel, size int64, expiresAt types.String) {
	model.Size = types.Int64Value(size)
	model.Generation = types.Int64Value(size)
	model.Slots = initialSlots(size, expiresAt)
	model.ActiveSlot = types.StringValue("0")
	model.ActiveGeneration = types.Int64Value(1)
	model.AcknowledgedGeneration = types.Int64Value(1)
	model.RolloutPending = types.BoolValue(false)
	model.RolloutDeadline = types.StringNull()
}

func rotationSlotValue(generation int64, expiresAt types.String) types.Object {
	return types.ObjectValueMust(rotationSlotAttributeTypes, map[string]attr.Value{
		"generation": types.Int64Value(generation),
		"expires_at": expiresAt,
	})
}

func resolveUnknownExpirations(model *rotationResourceModel, policy rotationPolicy, now time.Time) {
	unknownCount := 0
	for _, value := range model.Slots.Elements() {
		expiration := value.(types.Object).Attributes()["expires_at"].(types.String)
		if expiration.IsNull() || expiration.IsUnknown() {
			unknownCount++
		}
	}
	initialSchedule := unknownCount == int(policy.size) && model.Generation.ValueInt64() == policy.size

	elements := make(map[string]attr.Value, len(model.Slots.Elements()))
	for key, value := range model.Slots.Elements() {
		slot := value.(types.Object)
		attributes := slot.Attributes()
		expiration := attributes["expires_at"].(types.String)
		if expiration.IsNull() || expiration.IsUnknown() {
			expiresAfter := policy.period
			if initialSchedule && key != "0" {
				slot, err := strconv.ParseInt(key, 10, 64)
				if err == nil {
					expiresAfter = policy.rotateBefore + time.Duration(slot)*policy.interval
				}
			}
			expiration = expirationValue(now.Add(expiresAfter))
		}
		elements[key] = rotationSlotValue(attributes["generation"].(types.Int64).ValueInt64(), expiration)
	}
	model.Slots = types.MapValueMust(rotationSlotType, elements)
}

func expirationValue(value time.Time) types.String {
	return types.StringValue(value.UTC().Format(time.RFC3339Nano))
}

func earliestRequestedExpiration(model rotationResourceModel) (time.Time, error) {
	var earliest time.Time
	for key, value := range model.Slots.Elements() {
		raw := value.(types.Object).Attributes()["expires_at"].(types.String).ValueString()
		expiresAt, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("slot %q expires_at is invalid: %v", key, err)
		}
		if earliest.IsZero() || expiresAt.Before(earliest) {
			earliest = expiresAt
		}
	}
	if earliest.IsZero() {
		return time.Time{}, fmt.Errorf("rotation has no credential slots")
	}
	return earliest, nil
}

func countExpiredSlots(model rotationResourceModel, now time.Time) (int, error) {
	expired := 0
	for key, value := range model.Slots.Elements() {
		raw := value.(types.Object).Attributes()["expires_at"].(types.String).ValueString()
		expiresAt, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return 0, fmt.Errorf("slot %q expires_at is invalid: %v", key, err)
		}
		if !now.Before(expiresAt) {
			expired++
		}
	}
	return expired, nil
}

func minTime(left, right time.Time) time.Time {
	if right.Before(left) {
		return right
	}
	return left
}

func rotationPlanAlreadyModified(plan, state rotationResourceModel) bool {
	return !plan.Generation.IsUnknown() && !state.Generation.IsUnknown() && plan.Generation.ValueInt64() != state.Generation.ValueInt64()
}
