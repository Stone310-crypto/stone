# Adaptive Chat Batch Protocol (Draft v1)

## Goal

Ensure all nodes converge on the same chat batch behavior while allowing dynamic tuning based on observed message load.

Current static behavior:
- `BATCH_MIN_MESSAGES = 20`
- `BATCH_MAX_WAIT_SECS = 10`

Target behavior:
- Global consistency (no permanent config drift between nodes)
- Adaptive batching when message throughput rises/falls
- Deterministic activation points to avoid consensus splits

## Core Principle

Runtime tuning must be deterministic at consensus level.

That means:
1. Parameters are versioned and identified by a config hash.
2. Parameter updates activate at a specific future block height.
3. Until activation, all nodes continue using previous values.
4. After activation, all validators must build blocks with the new values.

## Protocol Objects

## 1) ChatBatchParams

Fields:
- `version: u32`
- `min_messages: u16`
- `max_wait_secs: u16`
- `window_secs: u16` (EMA/control window, e.g. 60)
- `target_commit_latency_secs: u16` (e.g. 8)
- `min_bound_messages: u16` (hard lower bound, e.g. 5)
- `max_bound_messages: u16` (hard upper bound, e.g. 200)
- `min_bound_wait_secs: u16` (hard lower bound, e.g. 3)
- `max_bound_wait_secs: u16` (hard upper bound, e.g. 60)
- `effective_from_block: u64`
- `config_hash: [u8; 32]` (sha256 over canonical serialization)

## 2) ChatBatchTelemetry

Optional gossip telemetry for operator insight and future proposals:
- `node_id`
- `timestamp`
- `incoming_msgs_last_minute`
- `pending_pool_size`
- `avg_confirmation_latency_secs`
- `active_params_hash`

Telemetry is non-consensus and never directly changes behavior.

## Configuration Distribution

## Preferred: Governance-driven config update

1. A governance proposal creates a new `ChatBatchParams`.
2. Proposal accepted and finalized by existing governance rules.
3. Node stores the new params as `pending_config`.
4. Activation at `effective_from_block`.
5. From that block onward, validators use new params.

Advantages:
- Deterministic, auditable, rollback-capable
- Same trust model as other protocol-level changes

## Governance Integration (Current Codebase)

Observed governance model (already implemented):
- Dual voting: 50% node vote + 50% stake vote
- Quorum checks for both dimensions
- Timelock before execution
- Optional multisig for `critical` proposals

Recommended mapping for chat-batch parameter changes:
1. Use `critical` governance proposals for parameter updates.
2. Put serialized `ChatBatchParams` payload in proposal description (canonical JSON).
3. Require multisig approval before proposal can pass from voting to accepted.
4. Apply config only from `effective_from_block`, never immediately.

Rationale:
- In small networks, a single noisy node should not force throughput policy changes.
- `critical` + multisig reduces manipulation risk.

## Fallback: Admin-signed emergency config

For incidents only:
- Multisig-signed config package
- Includes `effective_from_block`
- Nodes verify signer set before accepting

## Adaptive Policy (How values are chosen)

Adaptation should propose values, not auto-apply immediately.

Controller input:
- `msg_rate = incoming messages per minute`
- `pending = current message_pool pending size`
- `latency = observed pending-to-confirmed latency`

Proposed control law:
- `min_messages_dyn = clamp(round(msg_rate * alpha), min_bound_messages, max_bound_messages)`
- `max_wait_dyn = clamp(round(target_commit_latency_secs * beta / max(1, msg_rate_norm)), min_bound_wait_secs, max_bound_wait_secs)`

Practical simpler tiered model (recommended for v1):
- Low load (`msg_rate < 10`): `min=8`, `wait=8s`
- Medium load (`10 <= msg_rate < 60`): `min=20`, `wait=10s`
- High load (`msg_rate >= 60`): `min=50`, `wait=5s`

Hysteresis:
- Tier switch only if condition holds for N consecutive windows (e.g. 3 windows)
- Prevents oscillation/flapping

## Small-Network Profile (Recommended)

Use this profile when validator count is low (e.g. <= 7 trusted validators).

Policy:
1. Telemetry gate:
- At least 2 independent validators must report overload for >= 3 windows.
- A single node report is never sufficient.

2. Proposal gate:
- Only trusted nodes can create proposal (existing governance rule).
- Category must be `critical`.
- Require multisig threshold before acceptance.

3. Activation safety:
- `effective_from_block >= current_height + 30`.
- Cooldown: no second batch-param change within 120 blocks.

4. Guardrails:
- `min_messages` in [5, 200]
- `max_wait_secs` in [3, 60]
- Reject proposal payload outside bounds.

5. Anti-flap:
- If previous change is younger than cooldown, proposal may pass voting but remains non-executable until cooldown end.

This keeps small clusters stable while still allowing adaptation under real load.

## Consensus Safety Rules

1. Validator must include `active_params_hash` in block metadata once protocol field exists.
2. Peer rejects conflicting block if hash does not match active config at that height.
3. Config activation requires lead time:
- `effective_from_block >= current_height + safety_margin`
- suggested `safety_margin = 30` blocks
4. During grace window, nodes can prefetch but not apply.

## Backward Compatibility Path

Phase 0 (now): static constants in code.

Phase 1:
- Move constants to runtime config with same defaults.
- Keep local-only behavior, no consensus check yet.

Phase 2:
- Add governance object `ChatBatchParams` persisted in chain state.
- Add `effective_from_block` activation.

Phase 3:
- Add block-level `active_params_hash` validation.
- Enforce consensus safety.

Phase 4:
- Add adaptive proposal engine (telemetry -> proposal suggestion), human/governance approved.

## Operator UX

Required endpoints:
- `GET /api/v1/chat/batch/params` (active + pending)
- `GET /api/v1/chat/batch/telemetry`
- `POST /api/v1/chat/batch/propose` (auth + governance flow)

Node startup logs should print:
- Active params version/hash
- Pending params and activation height

## Immediate Practical Step

Before full protocol rollout:
1. Make `BATCH_MIN_MESSAGES` and `BATCH_MAX_WAIT_SECS` env-configurable.
2. Add cluster check endpoint to compare active values across nodes.
3. Alert if mismatch persists for more than one control window.

Status in this repository:
- Step 1 implemented with bounded env overrides:
	- `STONE_CHAT_BATCH_MIN_MESSAGES` (clamped to 5..200)
	- `STONE_CHAT_BATCH_MAX_WAIT_SECS` (clamped to 3..60)

This gives operational safety now and prepares consensus-safe rollout later.
