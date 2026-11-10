# GPU Passport v0

Live page: https://karrvel.github.io/gpu-passport/

Signed, delay-bounded location evidence for a GPU host. A verifier at an anchor sends fresh nonces over UDP;
the prover (next to the GPU) signs `nonce || gpu_uuid` with an ed25519 key; the verifier takes the **minimum RTT
over 100 rounds** and issues a signed certificate: the signer is at most `RTT/2 × 200 km/ms` from the anchor.

## What a certificate claims
"Key K answered fresh nonce N within R ms from anchor A, so the signer is within R/2 × 200 km of A (network-path bound)."
It does **not** establish jurisdiction, exact location, or that the key sits in a real GPU.

## Results (2026-11-10, anchor = a Mac in Tashkent, public IP geolocates to Tashkent)
| Test | Min RTT | Bound |
|---|---|---|
| Prover on GCP e2-micro, europe-west1 (CPU only, `gpu_uuid: no-gpu`) | 98.9 ms | ≤ 9,886 km |
| Same prover, challenges relayed through a process in Tashkent | 100.3 ms | ≤ 10,032 km (relay detected as far) |
| Second MacBook on the same Wi-Fi network (no GPU) | 3.67 ms | ≤ 367 km (median 5.4 ms; Wi-Fi jitter) |
| NVIDIA T4 on Modal, tunnel ingress Ashburn (US East) | 176.8 ms | ≤ 17,681 km |
| NVIDIA T4 on Modal, tunnel ingress San Jose (US West) | 248.8 ms | ≤ 24,882 km |
| NVIDIA RTX 5070 PC, same network in Tashkent | 3.19 ms | ≤ 319 km |
| Self-test, localhost | 0.16 ms | ≤ 16 km |

Bounds are loose upper bounds: real paths are longer than great-circle (true distance ≈ 4,800 km).

## Known limits (do not overclaim)
- **Copyable key.** The prover key is a software file. Copy it to a box near the anchor and the certificate passes. Defence = bind the key to hardware attestation (NVIDIA confidential computing / nvtrust, Hopper+/Blackwell) — not in v0.
- **One anchor** proves "within X km of the anchor", never "in Uzbekistan". Shymkent (KZ) is ~120 km from Tashkent; a border cannot be resolved by delay alone. Needs ≥3 anchors, one abroad, plus site registration.
- Delay padding only makes a host look farther away, never closer.
- Modal tunnels add an ingress hop, so those bounds are upper limits on the container, never falsely tight.
- Not endorsed by NVIDIA. Consumer GPUs (RTX 5070) and T4 give a real GPU ID but no hardware attestation.

## Run
`uv run --script gpupassport.py selftest | prover [--tcp] | relay | verify [--tcp] | check` (prover on the GPU host, verify from the anchor). Cloud GPUs: `modal run modal_prover.py --gpu T4`.
