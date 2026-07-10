import time
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ITERATIONS = 1000

print(f"[*] Benchmarking X25519 ({ITERATIONS} iterations)...")
start = time.perf_counter()
for _ in range(ITERATIONS):
    priv = X25519PrivateKey.generate()
    peer_priv = X25519PrivateKey.generate()
    shared = priv.exchange(peer_priv.public_key())
x25519_total = time.perf_counter() - start
print(f"    Total: {x25519_total:.4f}s | Avg: {(x25519_total/ITERATIONS)*1000:.4f} ms/op")

print(f"\n[*] Benchmarking ML-KEM-1024 ({ITERATIONS} iterations)...")
start = time.perf_counter()
with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
    for _ in range(ITERATIONS):
        public_key = kem.generate_keypair()
        ciphertext, shared_enc = kem.encap_secret(public_key)
        shared_dec = kem.decap_secret(ciphertext)
pqc_total = time.perf_counter() - start
print(f"    Total: {pqc_total:.4f}s | Avg: {(pqc_total/ITERATIONS)*1000:.4f} ms/op")

print("\n" + "="*45)
ratio = pqc_total / x25519_total
print(f"  ML-KEM-1024 is ~{ratio:.2f}x slower than X25519")
print(f"  >> Save this number for your thesis Data Point 1")
print("="*45)
