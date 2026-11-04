---
page_title: "stegra_rotation Resource"
---

# stegra_rotation

Coordinates multi-slot credential rotation without storing secret material. The
resource exposes monotonically increasing numeric generations that can drive
ordinary resource replacement, `keepers`, and `*_wo_version` arguments.

```hcl
resource "stegra_rotation" "example" {
  rotation_period = "2160h" # maximum intended credential age: 90 days
}
```

`rotation_period` is the only required policy. By default, the resource derives
`rotate_before` as `rotation_period / (size + 1)`, rotates one slot every
`(rotation_period - rotate_before) / size`, and uses that available interval as
the rollout window. With a 90-day period and two slots, these values are all 30
days.

Initial expirations are staggered to establish that cadence immediately. For a
90-day, two-slot rotation, slot `0` initially expires in 90 days and slot `1`
in 60 days. At day 30, slot `1` receives a new generation with a fresh 90-day
expiration; at day 60, slot `0` does the same.

When a rotation is overdue, one successful apply increments only the inactive
slot and makes it preferred. It schedules the next rotation relative to that
apply instead of catching up every missed interval, so a delayed pipeline never
rotates all slots back-to-back in a single apply. Every slot credential must
remain accepted by the target system while consumers converge.

After consumers have switched, set `acknowledged_generation` to the reported
`active_generation`. Until acknowledged, `rollout_pending` remains true and the
provider holds the next slot rotation. If acknowledgement is not recorded by
`rollout_deadline`, planning emits a warning while allowing failed consumer
updates to be retried. The previous credential is not rotated until the new
generation is acknowledged.

Changing policy never postpones an already scheduled rotation. A shorter safe
deadline may move rotation earlier, but extending the TTL cannot leave existing
credentials waiting beyond their previously calculated expiration. Changing
`rotation_period` leaves existing slot generations and expiration timestamps
unchanged; the new period applies when each slot is next rotated. For example,
changing from one year to two days gradually replaces the slots on the shorter
schedule, with acknowledgement required between rotations.

## Ordinary resources

Use `slots` directly with `for_each`, and use `each.value.generation` as a
`keeper` or replacement trigger. `each.value.expires_at` is stable
for that generation and advances only when its slot rotates. Secret values used by
ordinary resources remain in Terraform state.
See `examples/rotation/local` and `examples/rotation/gitlab`.

## Ephemeral and write-only resources

Retrieve or generate the slot value in an ephemeral block, then pass the
corresponding numeric slot generation to the destination's `*_wo_version`
argument. An ephemeral value must come from a durable backend if multiple
consumers need to converge safely across retries. See
`examples/rotation/aws-write-only`.

## Arguments

- `rotation_period` — required maximum intended credential age as a Go
  duration, such as `2160h` for 90 days.
- `size` — number of independently valid credential slots; defaults to `2` and
  requires replacement when changed.
- `rotate_before` — optional safety window; inferred when omitted.
- `rollout_timeout` — optional operational rollout budget; inferred when
  omitted.
- `acknowledged_generation` — latest preferred generation confirmed as deployed
  to consumers. It is initialized to `1` and must advance after each rotation.

## Read-only attributes

- `id` — stable opaque string identifier.
- `generation` — global rotation-event counter. Do not use it as a per-slot
  write-only version; use `slots[*].generation`.
- `slots` — iterable map keyed from `"0"` through `"size-1"`. Each value contains
  a numeric `generation` and stable RFC3339 `expires_at` timestamp.
- `active_slot`, `active_generation` — currently preferred credential.
- `rollout_pending`, `rollout_deadline` — acknowledgement status and deadline
  for the preferred generation.
- `rotation_interval` — derived time between slot changes.
- `next_rotation_at` — RFC3339 timestamp set once during a successful apply.

The resource coordinates generations and rollout acknowledgement only. It does
not create, persist, verify, or revoke secrets, does not verify the actual
expiration returned by a downstream API, and does not run Terraform on a
schedule. `expires_at` is the expiration the downstream resource
should request.

Rotation is evaluated during planning. Scheduled automation must create a fresh
plan; applying an old saved plan does not re-evaluate a deadline that passed
after that plan was created. Missed schedules and expired requested deadlines
produce diagnostics, while recovery still advances at most one slot per apply.
