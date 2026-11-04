# Quality Gates

Commands mirror `.github/workflows/ci.yml`. Scope to touched crates (`-p <crate>`)
while iterating; run the workspace-wide form once before the final gate. The
Tauri client (`client-gui-tauri`) needs GTK/WebKit on Linux; on macOS it builds natively.

| Gate | Iterating | Final | Required |
|------|-----------|-------|----------|
| Format | `cargo fmt --all` | `cargo fmt --all --check` | Yes |
| Lint | `cargo clippy -p <crate> --all-targets --all-features -- -D warnings` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Yes |
| Tests | `cargo nextest run -p <crate> --all-features` | `cargo nextest run --workspace --all-features` | Yes |
| Doc tests | `cargo test -p <crate> --all-features --doc` | `cargo test --workspace --all-features --doc` | Yes |
| Integration | `cargo nextest run -p sbc-integration-tests` | same | When `sbc-*`, `proto-*` transaction/dialog/B2BUA, or config changed |
| Docs build | — | `cargo doc --workspace --no-deps --all-features` | When public API changed |
| Benches | `cargo bench -p <crate> -- --save-baseline new` | same, compare to baseline | When a hot path changed (transport, proto-sip parse, rtp/srtp, media engine, codecs, audit) |
| Supply chain | — | `cargo audit` | When `Cargo.toml`/`Cargo.lock` changed |
| Annotations | — | `rg -c "NIST 800-53 Rev5" crates \| awk -F: '{s+=$2} END {print s}'` (count should not drop) | Yes for code changes |
| Markdown | — | `npx markdownlint-cli "docs/**/*.md"` | When docs changed |

## Performance budget

- No heap allocation per RTP packet on the steady-state relay/SRTP path.
- No blocking I/O or `std::sync` lock held across `.await` on signaling or media tasks.
- Audit/CDR/syslog/state-sync hand-off is non-blocking (bounded channel, `try_send`), overflow counted.
- A regression > 10% on an existing bench is a MAJOR finding unless justified.

## Rules

- Record every command with exit status and the last relevant output lines in
  `qa-report.md`. "Tests pass" without the command is not evidence.
- Missing environment (no Linux deps, no network for integration, no cargo-nextest)
  → gate is **NOT RUN**, never PASS.
- No new `#[allow(clippy::...)]`, `#[ignore]`, or `unwrap()` on wire data
  without a justification comment and a finding entry.
