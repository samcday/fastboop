# Channel fixture harness

This harness generates deterministic stream fixtures under `build/channels-fixtures` (already gitignored).

Usage:

```bash
tools/channels/generate-fixtures.sh
```

Optional overrides:

- `FASTBOOP_CHANNEL_SEED` to change deterministic payload bytes
- `SOURCE_DATE_EPOCH` to pin fixture timestamps
- first positional arg to pick a different output directory

Then run:

```bash
cargo test -p fastboop-core channel_stream:: -- --nocapture
cargo test -p fastboop-core generated_fixtures_match_expected_stream_kinds -- --nocapture
```
