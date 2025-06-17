# algorithms/dsa_signature.py
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes

class DSASignature:
    def generate_keys(self):
        private_key = dsa.generate_private_key(key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign(self, message: str, private_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        return private_key.sign(message, hashes.SHA256())

    def verify(self, message: str, signature: bytes, public_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        try:
            public_key.verify(signature, message, hashes.SHA256())
            return True
        except Exception:
            return False
