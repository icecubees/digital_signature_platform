# tests/test_rsa.py
import unittest
from algorithms.rsa_signature import RSASignature

class TestRSASignature(unittest.TestCase):
    def test_sign_and_verify(self):
        rsa = RSASignature()
        priv, pub = rsa.generate_keys()
        msg = "Digital Signature Test"
        sig = rsa.sign(msg, priv)
        self.assertTrue(rsa.verify(msg, sig, pub))

    def test_invalid_signature(self):
        rsa = RSASignature()
        priv, pub = rsa.generate_keys()
        sig = rsa.sign("message1", priv)
        self.assertFalse(rsa.verify("message2", sig, pub))

if __name__ == '__main__':
    unittest.main()
