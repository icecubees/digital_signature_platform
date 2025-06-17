import unittest

from algorithms import rsa_signature, dsa_signature, ecdsa_signature

class TestSignatureAlgorithms(unittest.TestCase):

    def setUp(self):
        self.message = b"test messages"
        self.signers = {
            "RSA": rsa_signature,
            "DSA": dsa_signature,
            "ECDSA": ecdsa_signature
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
                # 篡改消息
                tampered_msg = self.message + b"!"
                self.assertFalse(signer.verify(tampered_msg, signature, public_key))

    def test_cross_algorithm_conflict(self):
        rsa_priv, rsa_pub = rsa_signature.generate_keys()
        dsa_priv, dsa_pub = dsa_signature.generate_keys()
        msg = self.message

        rsa_sig = rsa_signature.sign(msg, rsa_priv)
        self.assertFalse(dsa_signature.verify(msg, rsa_sig, dsa_pub))  # 不兼容

    def test_multiple_signatures(self):
        for name, signer in self.signers.items():
            with self.subTest(algorithm=name):
                priv, pub = signer.generate_keys()
                sig1 = signer.sign(self.message, priv)
                sig2 = signer.sign(self.message, priv)
                self.assertNotEqual(sig1, sig2)  # 每次应不同（随机性）
                self.assertTrue(signer.verify(self.message, sig2, pub))

if __name__ == '__main__':
    unittest.main()
