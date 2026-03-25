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
