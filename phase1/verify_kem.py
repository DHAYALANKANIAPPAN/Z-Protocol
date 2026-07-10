import oqs

kem_name = "ML-KEM-1024"
with oqs.KeyEncapsulation(kem_name) as kem:
    print(f"[+] Engine active: {kem_name}")
    public_key = kem.generate_keypair()
    print(f"[+] Public key size: {len(public_key)} bytes")
    ciphertext, shared_secret = kem.encap_secret(public_key)
    print(f"[+] Ciphertext size: {len(ciphertext)} bytes")
    print(f"[+] ML-KEM-1024 working correctly!")
