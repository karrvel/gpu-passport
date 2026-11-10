# Run a GPU Passport prover on a Modal GPU behind a raw TCP tunnel, for a few minutes.
#   uvx modal run modal_prover.py --gpu T4 --region us-east --minutes 4
# shortcut: Modal tunnels add their own ingress hop, so bounds are upper limits on the container's distance.
import modal

image = modal.Image.debian_slim().pip_install("cryptography>=43").add_local_file("gpupassport.py", "/root/gpupassport.py")
app = modal.App("gpupassport-prover", image=image)


def _serve(minutes: int):
    import sys, threading, time
    sys.path.insert(0, "/root")
    import gpupassport as gp
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    threading.Thread(target=gp.serve_tcp, args=(key, gp.gpu_uuid(), 8443), daemon=True).start()
    with modal.forward(8443, unencrypted=True) as t:
        host, port = t.tcp_socket
        print(f"GP_TUNNEL host={host} port={port} pub={gp.pub_b64(key)} gpu={gp.gpu_uuid()}", flush=True)
        time.sleep(minutes * 60)


@app.function(gpu="T4", timeout=900)
def prover(minutes: int = 4):
    _serve(minutes)


@app.local_entrypoint()
def main(gpu: str = "T4", region: str = "", minutes: int = 4):
    opts = {"gpu": None if gpu == "none" else gpu}
    if region:
        opts["region"] = region
    prover.with_options(**opts).remote(minutes)
