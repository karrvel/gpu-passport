#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography>=43"]
# ///
"""GPU Passport v0 — delay-bound location certificate.

  prover  : runs next to the GPU; signs (nonce, gpu_uuid) with its ed25519 key.
  verify  : runs at an anchor; times N signed challenges, takes the minimum RTT,
            and issues a signed certificate saying the prover is within X km of the anchor.
  check   : verifies a certificate's signature.
  selftest: runs prover+verifier on localhost and asserts the certificate is valid.

Claim made: an UPPER BOUND on distance (light in fiber ~200 km/ms, so d <= RTT/2 * 200).
It does NOT prove an exact location, nor that the key is bound to real hardware (see README).
"""
import argparse, base64, json, os, secrets, subprocess, sys, threading, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KM_PER_MS = 200.0  # speed of light in fiber, one way
b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s)


def load_key(path):
    if os.path.exists(path):
        return serialization.load_pem_private_key(open(path, "rb").read(), None)
    k = Ed25519PrivateKey.generate()
    open(path, "wb").write(k.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    os.chmod(path, 0o600)
    return k


def pub_b64(k):
    return b64(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def gpu_uuid():
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=uuid", "--format=csv,noheader"],
                             capture_output=True, text=True, timeout=5).stdout.strip()
        return out.splitlines()[0] if out else "no-gpu"
    except Exception:
        return "no-gpu"


def canon(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def serve_udp(key, uuid, port, relay_to=None):
    """UDP prover: sign nonce||gpu_uuid. With relay_to, forward the request to a remote prover (attack test)."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if relay_to else None
    while True:
        data, addr = sock.recvfrom(2048)
        if relay_to:
            fwd.sendto(data, relay_to)
            sock.sendto(fwd.recv(2048), addr)
        else:
            msg = {"nonce": data.decode(), "gpu_uuid": uuid}
            sock.sendto(json.dumps({**msg, "sig": b64(key.sign(canon(msg)))}).encode(), addr)


def measure(host, port, prover_pub, rounds):
    import socket
    pk = Ed25519PublicKey.from_public_bytes(unb64(prover_pub))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    rtts, uuid = [], None
    for i in range(rounds + 3):  # first 3 rounds are warm-up, not counted
        nonce = secrets.token_hex(16)
        t0 = time.perf_counter()
        sock.sendto(nonce.encode(), (host, port))
        resp = json.loads(sock.recv(2048))
        dt = (time.perf_counter() - t0) * 1000
        if resp["nonce"] != nonce:
            raise ValueError("nonce mismatch (replay?)")
        pk.verify(unb64(resp["sig"]), canon({"nonce": resp["nonce"], "gpu_uuid": resp["gpu_uuid"]}))
        uuid = resp["gpu_uuid"]
        if i >= 3:
            rtts.append(dt)
    return min(rtts), sorted(rtts)[len(rtts) // 2], uuid


def serve_tcp(key, uuid, port):
    """TCP prover (one nonce per line) for hosts that only expose TCP, e.g. Modal tunnels."""
    import socketserver

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            for line in self.rfile:
                msg = {"nonce": line.strip().decode(), "gpu_uuid": uuid}
                self.wfile.write(json.dumps({**msg, "sig": b64(key.sign(canon(msg)))}).encode() + b"\n")
                self.wfile.flush()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer(("0.0.0.0", port), H).serve_forever()


def measure_tcp(host, port, prover_pub, rounds):
    import socket
    pk = Ed25519PublicKey.from_public_bytes(unb64(prover_pub))
    s = socket.create_connection((host, port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # no Nagle delay in the RTT
    f = s.makefile("rwb")
    rtts, uuid = [], None
    for i in range(rounds + 3):
        nonce = secrets.token_hex(16)
        t0 = time.perf_counter()
        f.write(nonce.encode() + b"\n"); f.flush()
        resp = json.loads(f.readline())
        dt = (time.perf_counter() - t0) * 1000
        if resp["nonce"] != nonce:
            raise ValueError("nonce mismatch (replay?)")
        pk.verify(unb64(resp["sig"]), canon({"nonce": resp["nonce"], "gpu_uuid": resp["gpu_uuid"]}))
        uuid = resp["gpu_uuid"]
        if i >= 3:
            rtts.append(dt)
    return min(rtts), sorted(rtts)[len(rtts) // 2], uuid


def issue_cert(vkey, anchor, prover_pub, min_rtt, med_rtt, uuid, rounds):
    body = {
        "version": 0,
        "issued_at": int(time.time()),
        "anchor": anchor,
        "prover_pubkey": prover_pub,
        "gpu_uuid": uuid,
        "rounds": rounds,
        "min_rtt_ms": round(min_rtt, 3),
        "median_rtt_ms": round(med_rtt, 3),
        "max_distance_km": round(min_rtt / 2 * KM_PER_MS, 1),
        "claim": f"prover answered a fresh signed challenge within {min_rtt:.3f} ms, so it is at most "
                 f"{min_rtt / 2 * KM_PER_MS:.0f} km (network-path distance bound) from anchor '{anchor}'.",
        "limits": "does not establish jurisdiction; upper bound from one anchor; prover key is a copyable "
                  "software key (attestation: none), so a local relay holding a copied key is not detected",
    }
    return {"body": body, "verifier_pubkey": pub_b64(vkey), "sig": b64(vkey.sign(canon(body)))}


def check_cert(cert):
    Ed25519PublicKey.from_public_bytes(unb64(cert["verifier_pubkey"])).verify(unb64(cert["sig"]), canon(cert["body"]))
    return True


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("prover"); p.add_argument("--port", type=int, default=8443); p.add_argument("--key", default="prover.key"); p.add_argument("--tcp", action="store_true")
    r = sp.add_parser("relay", help="attack test: forward challenges to a remote prover")
    r.add_argument("--port", type=int, default=8443); r.add_argument("--to", required=True, help="host:port of real prover")
    v = sp.add_parser("verify"); v.add_argument("--host", required=True); v.add_argument("--port", type=int, default=8443)
    v.add_argument("--prover-pub", required=True); v.add_argument("--anchor", required=True); v.add_argument("--rounds", type=int, default=100)
    v.add_argument("--key", default="verifier.key"); v.add_argument("--out", default="certificate.json"); v.add_argument("--tcp", action="store_true")
    c = sp.add_parser("check"); c.add_argument("cert")
    sp.add_parser("selftest")
    a = ap.parse_args()

    if a.cmd == "prover":
        k = load_key(a.key)
        print("prover pubkey:", pub_b64(k), "gpu:", gpu_uuid(), flush=True)
        (serve_tcp if a.tcp else serve_udp)(k, gpu_uuid(), a.port)
    elif a.cmd == "relay":
        h, pt = a.to.rsplit(":", 1)
        serve_udp(None, None, a.port, relay_to=(h, int(pt)))
    elif a.cmd == "verify":
        mn, md, uuid = (measure_tcp if a.tcp else measure)(a.host, a.port, a.prover_pub, a.rounds)
        cert = issue_cert(load_key(a.key), a.anchor, a.prover_pub, mn, md, uuid, a.rounds)
        json.dump(cert, open(a.out, "w"), indent=2)
        print(cert["body"]["claim"], "->", a.out)
    elif a.cmd == "check":
        print("valid" if check_cert(json.load(open(a.cert))) else "INVALID")
    else:
        pk = Ed25519PrivateKey.generate()
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        threading.Thread(target=serve_udp, args=(pk, "GPU-selftest", port), daemon=True).start()
        time.sleep(0.3)
        mn, md, uuid = measure("127.0.0.1", port, pub_b64(pk), 20)
        cert = issue_cert(Ed25519PrivateKey.generate(), "localhost", pub_b64(pk), mn, md, uuid, 20)
        assert check_cert(cert) and uuid == "GPU-selftest" and cert["body"]["max_distance_km"] < 100, cert
        cert["body"]["max_distance_km"] = 0.0  # tampering must break the signature
        try:
            check_cert(cert); sys.exit("tamper not detected")
        except Exception as e:
            assert type(e).__name__ == "InvalidSignature"
        threading.Thread(target=serve_tcp, args=(pk, "GPU-selftest", port + 1), daemon=True).start()
        time.sleep(0.3)
        assert measure_tcp("127.0.0.1", port + 1, pub_b64(pk), 10)[2] == "GPU-selftest"
        print(f"selftest ok: min RTT {mn:.3f} ms (udp+tcp)")


if __name__ == "__main__":
    main()
