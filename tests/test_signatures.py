import unittest

from algorithms.rsa_signature import RSASignature
from algorithms.dsa_signature import DSASignature
from algorithms.ecdsa_signature import ECDSASignature

class TestSignatureAlgorithms(unittest.TestCase):

    def setUp(self):
        self.message = b"test messages"
        self.signers = {
            "RSA": RSASignature(),
            "DSA": DSASignature(),
            "ECDSA": ECDSASignature()
        }

    def test_sign_and_verify_all(self):
        for name, signer in self.signers.items():
            with self.subTest(algorithm=name):
                private_key, public_key = signer.generate_keys()
                signature = signer.sign(self.message, private_key)
                self.assertTrue(signer.verify(self.message, signature, public_key))

    def test_invalid_signature(self):
        for name, signer in self.signers.items():
            with self.subTest(algorithm=name):
                private_key, public_key = signer.generate_keys()
                signature = signer.sign(self.message, private_key)
                tampered_msg = self.message + b"!"
                self.assertFalse(signer.verify(tampered_msg, signature, public_key))

    def test_cross_algorithm_conflict(self):
        rsa = RSASignature()
        dsa = DSASignature()
        msg = self.message

        rsa_priv, rsa_pub = rsa.generate_keys()
        dsa_priv, dsa_pub = dsa.generate_keys()

        rsa_sig = rsa.sign(msg, rsa_priv)
        self.assertFalse(dsa.verify(msg, rsa_sig, dsa_pub))  # 不兼容

    def test_multiple_signatures(self):
        for name, signer in self.signers.items():
            with self.subTest(algorithm=name):
                priv, pub = signer.generate_keys()
                sig1 = signer.sign(self.message, priv)
                sig2 = signer.sign(self.message, priv)
                self.assertNotEqual(sig1, sig2)  # 每次应不同（有随机性）
                self.assertTrue(signer.verify(self.message, sig2, pub))

#python -m unittest discover -s tests

if __name__ == '__main__':
    unittest.main()
