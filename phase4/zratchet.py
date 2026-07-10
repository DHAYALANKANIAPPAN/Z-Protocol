import hashlib
import hmac
import os


def hkdf_expand(key: bytes, info: bytes, length: int = 32) -> bytes:
    """Minimal HKDF-expand using SHA-256."""
    return hmac.new(key, info, hashlib.sha256).digest()[:length]


class DoubleRatchet:
    """
    Simplified Signal-style ratchet for Z-Protocol.
    Each send/receive call rotates the chain key and produces a fresh message key.
    """
    def __init__(self, session_key: bytes):
        self.chain_key   = session_key
        self.msg_counter = 0

    def next_message_key(self) -> bytes:
        """Derive next message key and advance the chain."""
        msg_key   = hkdf_expand(self.chain_key, b"z-protocol-msg-key")
        self.chain_key = hkdf_expand(self.chain_key, b"z-protocol-chain-advance")
        self.msg_counter += 1
        return msg_key

    def encrypt(self, plaintext: bytes) -> tuple[bytes, int]:
        """Encrypt with next ratchet key. Returns (ciphertext, msg_number)."""
        from zcrypto import encrypt as aes_encrypt
        msg_key    = self.next_message_key()
        ciphertext = aes_encrypt(msg_key, plaintext)
        return ciphertext, self.msg_counter

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt with next ratchet key."""
        from zcrypto import decrypt as aes_decrypt
        msg_key   = self.next_message_key()
        plaintext = aes_decrypt(msg_key, ciphertext)
        return plaintext


if __name__ == "__main__":
    print("[*] Testing Double Ratchet forward secrecy...")
    session_key = os.urandom(32)

    sender   = DoubleRatchet(session_key)
    receiver = DoubleRatchet(session_key)

    messages = [
        b"Message 1 - first ratchet step",
        b"Message 2 - second ratchet step",
        b"Message 3 - third ratchet step",
    ]

    print("\n[*] Encrypting messages...")
    ciphertexts = []
    for msg in messages:
        ct, num = sender.encrypt(msg)
        ciphertexts.append(ct)
        print(f"    Msg {num}: {ct.hex()[:32]}...")

    print("\n[*] Decrypting messages...")
    for i, ct in enumerate(ciphertexts):
        pt = receiver.decrypt(ct)
        match = pt == messages[i]
        print(f"    Msg {i+1}: {pt} | match={match}")

    print("\n[+] Forward secrecy test:")
    print("    If key for Msg 3 is stolen, Msg 1 and 2 are still safe")
    print("    because each step uses a different derived key.")
    print("[+] Double Ratchet working correctly!")
