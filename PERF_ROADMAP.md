# Performance Optimization Roadmap

Prioritized list of optimization opportunities across the audio pipeline, protocol stack, and build system.

---

## Critical (highest ROI)

### 1. ~~Cache SRTP AES-256-GCM keys~~ DONE
- **Commit:** `perf/proto-crate-optimizations`
- Added `CachedAeadKey` wrapping `LessSafeKey` in `uc-crypto`. Pre-expands AES key schedule once in `SrtpContext` constructor. All `protect`/`unprotect` calls now use cached keys (~100ns saved per packet).

### 2. ~~Add release build profile~~ DONE
- **Commit:** `perf/proto-crate-optimizations`
- Added `[profile.release]` with `lto = "fat"`, `codegen-units = 1`, `opt-level = 3`, `strip = true`. Per-crate overrides for audio and protocol hot-path crates.

### 3. ~~Kaiser window + sinc LUT for fractional resampler~~ DONE
- **Commit:** `perf/proto-crate-optimizations`
- Pre-computed 1025-entry Kaiser window LUT and 2049-entry sinc LUT (~25 KB). Replaces per-tap `bessel_i0()` (25 iterations) and `sin()`/division with table lookup + linear interpolation.

---

## High (measurable improvement)

### 4. ~~Circular buffer for resampler history~~ DONE
- **Commit:** `perf/proto-crate-optimizations`
- Both polyphase and fractional resamplers now use double-length circular buffers. Eliminates `copy_within` shift (60 bytes → 8 bytes per sample for polyphase, 64 → 8 for fractional). SIMD dot product unchanged via `unsafe` contiguous view.

### 5. Lock-free pipeline stats — SKIPPED
- Per-packet counters already use `AtomicRtpStats` (lock-free). The `Mutex<PipelineStats>` is only locked every ~100 frames (~2s) for aggregate reporting. Contention is negligible.

### 6. Stereo downmix bit-shift — SKIPPED
- Compiler already optimizes `/ 2` to `>> 1` for integer stereo downmix. No measurable improvement.

### 7. ~~AEC inner loop modulo elimination~~ DONE
- **Commit:** `perf/proto-crate-optimizations`
- AEC reference history now uses double-buffer technique. Eliminates all `% filter_len` operations from the NLMS convolution and update loops (~330K modulo ops/frame for 1024-tap filter). Also pre-multiplied `norm * error` outside the NLMS update loop.

---

## Medium (polish, allocation reduction)

### 8. ~~Pre-allocate hot-path scratch buffers~~ PARTIAL
- **Commit:** `perf/proto-crate-optimizations`
- RFC 2198 header parsing now uses stack-allocated `[(u8, u32, usize); 4]` instead of `Vec::new()`. Remaining items (PLC, DTMF scratch buffers) are lower priority.

### 9. ~~Replace `Bytes::clone()` with `put_slice()` in RTP serialization~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- Replaced `buf.put(self.payload.clone())` with `buf.put_slice(&self.payload)` in both `RtpPacket::to_bytes()` and `RtcpPacket::to_bytes()`. Direct memcpy instead of refcount bump.

### 10. ~~Single-pass energy computation~~ DONE
- **Commit:** `perf/proto-crate-optimizations`
- VAD's `compute_rms()` + `compute_zcr()` merged into `compute_rms_and_zcr()` — single pass over PCM buffer computes both RMS energy and zero-crossing rate.

### 11. ~~`Vec::with_capacity()` for extension element parsing~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- `parse_one_byte_elements()` now uses `Vec::with_capacity(4)`, `parse_two_byte_elements()` uses `Vec::with_capacity(8)`. Avoids 1-2 reallocations per parsed extension header.

### 12. ~~Jitter buffer sort scratch on stack~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- Removed `sort_scratch: Vec<f32>` field from `JitterBuffer`. `percentile_95()` now uses a local `[f32; JITTER_HISTORY_SIZE]` stack array (800 bytes). Eliminates heap allocation every 50 packets.

---

## Low (correctness/cleanup, rare paths)

### 13. ~~SRTP replay window lock contention~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- Replaced `HashSet<u64>` with a 64-bit bitmap for replay detection. Bit `(highest - index)` tracks each received index. Eliminates per-packet hashing, heap allocation, and `retain()` on window shifts. Removed `Arc` wrapper (owned `Mutex<ReplayWindow>` directly).

### 14. ~~RTP translator unnecessary clones~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- Changed `forward_packet(&RtpPacket)` to `forward_packet(RtpPacket)` — takes ownership instead of borrowing. SSRC translation mutates the header in-place. Eliminates `header.clone()` and `payload.clone()` on every forwarded packet.

### 15. ~~Decode thread duplicate peak tracking~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- Post-gain peak amplitude now tracked inside the gain-application loop itself, eliminating the second `.iter().map().max()` pass over the output buffer.

### 16. ~~PLC concealment buffer reuse~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- `PacketLossConcealer` now stores `synth_scratch: Vec<f32>` and `result_scratch: Vec<i16>` for reuse across calls. `conceal()` returns `&[i16]` instead of `Vec<i16>`, eliminating per-frame heap allocation during loss bursts.

### 17. ~~Noise gate reciprocal precomputation~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- Precomputes `inv_fade_len = 1.0 / fade_len as f32` before the fade-out loop. Per-sample computation uses multiply instead of divide.

---

## Additional (discovered post-roadmap)

### 18. ~~SRTP seal/open per-packet allocation~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- Fixed `CachedAeadKey::open()` double allocation: replaced second `plaintext.to_vec()` with in-place `truncate()`. Added `seal_into()`/`open_into()` methods accepting caller-provided `&mut Vec<u8>` buffers. `RtpTransmitter` stores `srtp_scratch: Vec<u8>` reused across all `protect_rtp_parts_into()` calls. Eliminates one ~180-byte heap alloc per outbound packet (50/sec).

### 19. ~~WSOLA PLC output buffer reuse~~ DONE

- **Commit:** `perf/proto-crate-optimizations`
- `WsolaPlc` now stores `output: Vec<i16>` and `conceal()` returns `&[i16]` instead of `Vec<i16>`. Also replaced `repeat_last_frame()` heap allocation (`to_vec()`) with `copy_within`. Eliminates per-conceal allocation during loss bursts.

### 20. RTP extension header clone — SKIPPED

- `ExtensionHeader` contains `Bytes` (Arc-refcounted). Clone cost is ~2ns (refcount bump). Not worth optimizing.

---

## Missing Benchmarks

The following components lack criterion benchmarks in `crates/client/client-audio/benches/audio_hotpaths.rs`:

- [ ] VAD (`compute_rms`, `compute_zcr`, `detect`)
- [ ] AEC filter convolution per-frame
- [ ] Postfilter (de-emphasis, comfort noise mixing)
- [ ] Comfort noise generation
- [ ] Drift compensator update
- [ ] AGC + noise gate processing chain
- [ ] DTMF tone generation
- [ ] PLC concealment (WSOLA)
- [ ] Full I/O thread frame cycle (capture + encode + send)

Adding these enables before/after measurement for each optimization above.

---

## SBC 0.10.0 baseline: STIR/SHAKEN and SIP transport

Added for POA&M-38 and POA&M-50. Machine: Apple M2 Max (12 cores, 32 GB),
macOS 27.0.1, rustc 1.99.1, `bench` profile, with
other work running on the machine. Numbers are the criterion point estimate from
`-- --quick` runs on 2026-11-06 (main at 861c23a). Treat them as a reference
for regressions on the same machine, not as absolute capacity.

```bash
cargo bench -p proto-stir-shaken --bench passport -- --quick
cargo bench -p uc-sti --bench sti_cache -- --quick
cargo bench -p uc-transport --bench transport_rtt -- --quick
```

### `proto-stir-shaken` (`benches/passport.rs`)

Real ES256 via `uc-crypto::interop::ecdsa_p256` (aws-lc).

| Bench | Time |
|---|---|
| `passport_sign_es256` (sign + encode, one dest) | 17.6 µs |
| `passport_encode_noop_signer` (JSON + base64 only) | 0.52 µs |
| `identity_header_parse` (full-form token, info/alg/ppt) | 0.79 µs |
| `verifier_prepare` (parse + decode) | 1.88 µs |
| `verifier_verify_es256_warm_key` (ECDSA verify + claim checks) | 43.0 µs |
| `verifier_prepare_plus_verify` | 45.0 µs |
| `reject_oversize_identity` (8 KiB value, length cap) | 4 ns |
| `reject_malformed_max_token` (~4 KB token, bad base64 at end) | 5.1 µs |

### `uc-sti` (`benches/sti_cache.rs`)

| Bench | Time |
|---|---|
| `cache_hit_key_resolver_cached` (`KeyResolver::cached`) | 62 ns |
| `cache_hit_get_or_fetch_block_on` (warm path, includes `block_on`) | 150 ns |
| `cache_miss_fill_evict_at_cap16` (fake source; chain validation + insert + evict + task spawn) | 62 µs |
| `aggregator_record_hit` (`FailureAggregator::record`, same key in window) | 33 ns |
| `lru_insert_evict_at_cap256` (one full shard) | 117 ns |
| `lru_get_hit_cap256` (256 gets) | 5.9 µs (23 ns/get) |

### `uc-transport` (`benches/transport_rtt.rs`)

One iteration = client send, server recv, server send, client recv on
127.0.0.1 (single-threaded runtime). TCP/TLS use the split read/write halves.

| Bench | 600 B | 4 KB |
|---|---|---|
| TCP round trip | 18.9 µs | 16.6 µs |
| TLS 1.3 round trip (P-384 cert, AES-256-GCM) | 20.1 µs | 26.2 µs |
| UDP round trip | 26.2 µs | n/a (`MAX_UDP_MESSAGE_SIZE` = 1300) |

### Reading the numbers

- Verifying one inbound SHAKEN Identity costs about 45 µs of CPU, almost all
  of it the ECDSA P-256 verify; signing one costs about 18 µs. The cache hit
  (62 ns) and aggregator (33 ns) are negligible next to that.
- Rejecting a malformed token costs at most ~5 µs, about a ninth of a valid
  verify; oversize values are rejected by the length cap at once.
- The 3-8% INVITE throughput estimate for STIR is not confirmed or refuted
  here: that needs the INVITE-to-180 daemon bench, which is still missing.
- Loopback round trips are dominated by syscalls and the runtime, not TLS:
  TLS adds ~1 µs at 600 B and ~10 µs at 4 KB over TCP. The UDP path was not
  changed in 0.10.0; its number is for comparison only. Quick-mode loopback
  numbers vary between runs (TCP 600 B measured 12.5 µs and 18.9 µs in two
  runs); compare with a full, non-`--quick` run before calling a regression.

### Still missing

- [ ] End-to-end INVITE-to-180 through `sbc-daemon`, with and without STIR
  (open under POA&M-38 / POA&M-50).
- [ ] `sbc-daemon` flow table and per-destination lane enqueue/dispatch
  (`flows.rs`, `FlowTable::lane_busy`; open under POA&M-50, see POA&M-55).
