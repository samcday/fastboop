# gibblox-pipeline optimization plan (fragment dedup)

## Context

`fastboop bootprofile create --optimize-pipeline-hints` currently optimizes rootfs/kernel/dtbs pipelines independently. If those pipelines share the same expensive upstream fragment (for example `android_sparseimg <- xz <- file`), the same sparse index materialization work is repeated.

This plan focuses on fixing that in `gibblox-pipeline`, so all consumers can reuse work across multiple optimization calls in one process.

## Goals

1. Reuse expensive optimization artifacts across multiple pipelines in the same run.
2. Keep existing behavior unchanged when callers do not opt into shared-session optimization.
3. Preserve deterministic outputs and existing validation semantics.
4. Improve observability (reporting cache hits/reuse).

## Non-goals

- No behavior change to runtime read path or pipeline execution semantics.
- No global persistent cache format changes in this phase.
- No fastboop-specific hacks in `gibblox-pipeline` internals.

## High-level design

Introduce an optimizer session object that owns reusable state:

- New type: `OptimizePipelineSession`.
- Session holds an in-memory cache keyed by fragment identity.
- New entrypoint: `optimize_pipeline_with_session(source, opts, session)`.
- Keep existing `optimize_pipeline(source, opts)` as a convenience wrapper that creates a throwaway session.

### Cache key strategy

Use fragment identity at the `android_sparseimg.source` boundary (not full top-level pipeline identity):

- Key should represent the exact upstream bytes feeding sparse parsing.
- For now, use a normalized identity string produced by existing source identity machinery.
- Include enough variant data to avoid false reuse (compression/source chain differences).

### Reuse behavior

When optimizing a pipeline containing `android_sparseimg`:

1. Compute fragment key for `android_sparseimg.source`.
2. If cache hit and not forcing refresh, reuse stored sparse index.
3. If miss (or forced refresh), materialize index and store in session cache.
4. Continue normal optimization traversal/reporting.

## API sketch

```rust
pub struct OptimizePipelineSession { /* internal caches */ }

impl OptimizePipelineSession {
    pub fn new() -> Self;
}

pub async fn optimize_pipeline_with_session(
    source: &mut PipelineSource,
    opts: &OptimizePipelineOptions,
    session: &mut OptimizePipelineSession,
) -> Result<OptimizePipelineReport, PipelineError>;

pub async fn optimize_pipeline(
    source: &mut PipelineSource,
    opts: &OptimizePipelineOptions,
) -> Result<OptimizePipelineReport, PipelineError> {
    let mut session = OptimizePipelineSession::new();
    optimize_pipeline_with_session(source, opts, &mut session).await
}
```

## Report/telemetry updates

Extend `OptimizePipelineReport` with reuse metrics:

- `android_sparse_indexes_reused`
- `android_sparse_index_cache_hits`
- `android_sparse_index_cache_misses`

Keep existing counters intact.

## Implementation steps

1. Add `OptimizePipelineSession` and new session-aware optimize entrypoint.
2. Refactor current optimizer internals to accept shared mutable session state.
3. Implement android sparse fragment cache lookup/store in optimizer path.
4. Update report counters for hit/miss/reuse.
5. Keep no-session wrapper behavior 1:1 with current behavior.
6. Add docs/comments for cache key and force semantics.

## Test plan

### Unit tests

1. Single pipeline optimize still works with wrapper API.
2. Two pipelines with identical sparse fragment and shared session:
   - first call materializes index,
   - second call reuses index,
   - report counters reflect hit/reuse.
3. Distinct sparse fragments do not cross-reuse.
4. `force=true` bypasses reuse and refreshes cached entry.
5. Existing index in source + `force=false` keeps current skip behavior.

### Integration/behavior tests

1. A profile-like scenario (rootfs/kernel/dtbs sharing source) shows reduced repeated work.
2. Output pipelines are semantically equivalent to pre-change results.

## Performance validation

Capture before/after for representative large sparse+xz inputs:

- wall time,
- bytes read from upstream source,
- number of sparse index materializations.

Success criteria: multi-pipeline optimize time approaches one materialization cost plus small overhead, not Nx materialization cost.

## Risks and mitigations

- **Risk:** incorrect cache key causes false reuse.
  - **Mitigation:** include full fragment identity chain; add non-reuse regression tests.
- **Risk:** force semantics become confusing.
  - **Mitigation:** explicitly define and test `force` behavior with session cache.
- **Risk:** memory growth in long sessions.
  - **Mitigation:** start with simple bounded map policy if needed; document current behavior.

## fastboop follow-up (separate change)

After upstream API lands:

1. Create one optimizer session per `bootprofile create` invocation.
2. Run rootfs/kernel/dtbs optimization through that shared session.
3. Log/report reuse counters in fastboop CLI output.
