# Report Formats

## Findings file (`findings-<role>.md`)

```markdown
# Findings — <role>

Scope: <base>...<head> (<n> files), plan: <run>/plan.md
Verdict: APPROVE | APPROVE WITH COMMENTS | CHANGES REQUESTED

## <ROLE-PREFIX>-001 [BLOCKER] <one-line title>

- **Location**: `crates/proto/proto-sip/src/file.rs:123`
- **Reference**: NIST 800-53 SC-5 | RFC 3261 §17.1 | CWE-...
- **Problem**: what is wrong, in one or two sentences.
- **Failure scenario**: concrete message/state → concrete bad outcome.
- **Fix**: the smallest change that resolves it.
- **Confidence**: high | medium | low
```

Role prefixes: `SEC` (security), `NIST` (800-53), `RFC` (protocol),
`PERF` (performance), `QA` (testing), `REL` (release).

### Severity

| Severity | Meaning | Gate effect |
|----------|---------|-------------|
| BLOCKER | Remote crash/panic from a message, memory unsafety, ACL/auth bypass, toll fraud, media hijack or misrouted calls, crypto downgrade, audit bypass or lost attribution, broken RFC MUST | Must fix |
| MAJOR | Missing required control/test, DoS amplification or unbounded state, RFC SHOULD violated without reason, fail-open path, >10% hot-path regression, blocking call on signaling/media path | Must fix |
| MINOR | Hardening, missing annotation, weak test, unclear error type, small perf win | Advisory |
| NIT | Style, naming, comments | Advisory |

A finding without a location and a failure scenario is MINOR at most.

## Fix response (`fixes-round-<n>.md`)

```markdown
| Finding | Action | Change |
|---------|--------|--------|
| SEC-001 | Fixed | `header.rs:120-131` bound header count before allocating |
| RFC-002 | Rebutted | RFC 3261 §16.3 permits dropping the request |
```

## Gate summary (`gate.md`)

```markdown
# Gate — <task>

Verdict: PASS | PASS WITH POA&M | FAIL

| Gate | Result | Evidence |
|------|--------|----------|
| fmt | PASS | `cargo fmt --all --check` |
| clippy | PASS | `cargo clippy --workspace ...` |
| integration | PASS | `cargo nextest run -p sbc-integration-tests` |
| tests | PASS (212) | `cargo nextest run --workspace` |
| benches | PASS (srtp/protect −2%) | `cargo bench -p proto-srtp` |
| security review | APPROVE | findings-security.md |
| NIST 800-53 review | APPROVE WITH COMMENTS | findings-nist.md (2 MINOR) |
| RFC review | APPROVE | findings-rfc.md |
| performance review | APPROVE | findings-perf.md |
| compliance docs | UPDATED | docs-update.md |
| release | CHANGELOG (SBC) | release-notes.md |

## Open items
## POA&M
## Dropped findings
```
