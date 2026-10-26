"""Tests of the cryptocalc Python package (run by CTest with PYTHONPATH=build/python)."""
import hashlib
import hmac
import os
import tempfile
import unittest

import cryptocalc as cc
from cryptocalc import CryptoError, HashFunction, SecurityLevel

MSG = b"Hello, crypto-calcul!"


class HashTest(unittest.TestCase):
    def test_matches_hashlib(self):
        cases = [
            (cc.MD5(), hashlib.md5), (cc.SHA1(), hashlib.sha1),
            (cc.SHA224(), hashlib.sha224), (cc.SHA256(), hashlib.sha256),
            (cc.SHA384(), hashlib.sha384), (cc.SHA512(), hashlib.sha512),
            (cc.SHA3_224(), hashlib.sha3_224), (cc.SHA3_256(), hashlib.sha3_256),
            (cc.SHA3_384(), hashlib.sha3_384), (cc.SHA3_512(), hashlib.sha3_512),
        ]
        for ours, reference in cases:
            for message in (b"", b"abc", MSG * 50):
                self.assertEqual(ours.hash(message), reference(message).digest())

    def test_shake_is_incremental(self):
        shake = cc.SHAKE256()
        shake.update(MSG)
        shake.xof()
        out = shake.squeeze(10) + shake.squeeze(54)
        self.assertEqual(out, hashlib.shake_256(MSG).digest(64))
        shake.update(b"more")
        self.assertEqual(shake.squeeze(32), hashlib.shake_256(MSG + b"more").digest(32))
        self.assertEqual(cc.SHAKE128().squeeze(16), hashlib.shake_128(b"").digest(16))


class RandomAndPrimeTest(unittest.TestCase):
    def test_random(self):
        rng = cc.RNG()
        self.assertLess(rng.rand_int_b(100), 2 ** 100)
        self.assertLess(rng.rand_int_m(1000), 1000)
        self.assertEqual(len(rng.rand_bytes(33)), 33)
        with self.assertRaises(CryptoError):
            rng.rand_int_m(0)

    def test_seeded_is_reproducible(self):
        a, b = cc.RNG(1234), cc.RNG(1234)
        self.assertEqual([a.rand_int_b(512) for _ in range(3)], [b.rand_int_b(512) for _ in range(3)])

    def test_primes(self):
        prime = cc.Prime()
        self.assertTrue(prime.test(2 ** 127 - 1))
        self.assertFalse(prime.test(2 ** 127 + 1, test=cc.PrimalityTest.FERMAT))
        self.assertTrue(prime.test(3, test=cc.PrimalityTest.FERMAT))
        p = prime.gen_prime_b(256)
        self.assertEqual(p.bit_length(), 256)
        self.assertTrue(prime.test(p, test=cc.PrimalityTest.GMP))
        self.assertLess(prime.gen_prime_m(10 ** 9), 10 ** 9)
        with self.assertRaises(CryptoError):
            prime.gen_prime_m(0)


class SymmetricTest(unittest.TestCase):
    def test_aes_all_modes(self):
        for level in (SecurityLevel.L1, SecurityLevel.L2, SecurityLevel.L3):
            for mode in cc.AESMode:
                aes = cc.AES(level, mode)
                ct = aes.encrypt(MSG, b"key", b"iv", b"nonce")
                self.assertEqual(aes.decrypt(ct, b"key", b"iv", b"nonce"), MSG)

    def test_aes_errors(self):
        aes = cc.AES(SecurityLevel.L1, cc.AESMode.CBC)
        ct = aes.encrypt(MSG, b"key", b"iv")
        with self.assertRaises(CryptoError) as error:
            aes.decrypt(ct, b"wrong key", b"iv")
        self.assertEqual(str(error.exception), "Decryption failed")
        with self.assertRaises(CryptoError):
            aes.decrypt(ct[:-1], b"key", b"iv")
        with self.assertRaises(ValueError):
            cc.AES(SecurityLevel.L0, cc.AESMode.CBC)

    def test_des(self):
        des = cc.DES()
        ct = des.encrypt(MSG, b"secret")
        self.assertEqual(des.decrypt(ct, b"secret"), MSG)
        with self.assertRaises(CryptoError):
            des.decrypt(ct, b"Secret")

    def test_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain, enc, dec = (os.path.join(tmp, name) for name in ("plain.txt", "enc", "dec"))
            with open(plain, "wb") as f:
                f.write(MSG * 10)
            for cipher, args in ((cc.AES(SecurityLevel.L3, cc.AESMode.CTR), (b"key", b"nonce")), (cc.DES(), (b"key",))):
                cipher.encrypt_file(plain, enc, *args)
                cipher.decrypt_file(enc, dec, *args)
                with open(dec, "rb") as f:
                    self.assertEqual(f.read(), MSG * 10)
            with self.assertRaises(CryptoError) as error:
                cc.DES().encrypt_file(os.path.join(tmp, "missing"), enc, b"key")
            self.assertEqual(error.exception.status, cc._core.lib.CC_ERR_IO)

            tag = cc.HMAC(SecurityLevel.L1, HashFunction.SHA2).mac_file(plain, b"key")
            self.assertEqual(tag, hmac.new(b"key", MSG * 10, hashlib.sha256).digest())
            self.assertTrue(cc.HMAC(SecurityLevel.L1, HashFunction.SHA2).verify_file(plain, b"key", tag))

    def test_hmac_matches_python(self):
        cases = [(HashFunction.MD5, SecurityLevel.L0, hashlib.md5), (HashFunction.SHA1, SecurityLevel.L0, hashlib.sha1),
                 (HashFunction.SHA2, SecurityLevel.L3, hashlib.sha512), (HashFunction.SHA3, SecurityLevel.L1, hashlib.sha3_256)]
        for hash_function, level, reference in cases:
            mac = cc.HMAC(level, hash_function)
            for key in (b"Jefe", b"k" * 200):
                tag = mac.mac(key, MSG)
                self.assertEqual(tag, hmac.new(key, MSG, reference).digest())
                self.assertTrue(mac.verify(key, MSG, tag))
                self.assertFalse(mac.verify(key, MSG + b"!", tag))
                self.assertFalse(mac.verify(key, MSG, tag[:-1]))

    def test_cbc_mac(self):
        mac = cc.CBCMAC(SecurityLevel.L3)
        tag = mac.mac(b"key", MSG)
        self.assertEqual(len(tag), 16)
        self.assertTrue(mac.verify(b"key", MSG, tag))
        self.assertFalse(mac.verify(b"key", MSG + b"!", tag))
        with self.assertRaises(CryptoError):
            cc.CBCMAC(SecurityLevel.L0).mac(b"key", MSG)


class RSATest(unittest.TestCase):
    def test_variants(self):
        for variant in cc.RSAVariant:
            rsa = cc.RSA(SecurityLevel.L0, variant)
            with self.assertRaises(CryptoError):
                rsa.encrypt(b"x")
            rsa.keygen()
            message = b"\x01Hi" if variant == cc.RSAVariant.TEXTBOOK else b"\x00\x00Hi"
            ct = rsa.encrypt(message)
            for algo in cc.RSAAlgo:
                self.assertEqual(rsa.decrypt(ct, algo), message)
                signature = rsa.sign(message, algo)
                self.assertTrue(rsa.verify(message, signature))
                self.assertFalse(rsa.verify(message + b"!", signature))
            if variant != cc.RSAVariant.TEXTBOOK:
                with self.assertRaises(CryptoError):
                    rsa.decrypt(b"\xff" * len(ct))

    def test_keys(self):
        rsa = cc.RSA(SecurityLevel.L0, cc.RSAVariant.PKCS1)
        rsa.keygen()
        pub, prv = rsa.pubKey, rsa.prvKey
        self.assertEqual(pub.e, 65537)
        self.assertEqual(pub.n, prv.p * prv.q)
        self.assertEqual(pub.n.bit_length(), 2048)
        self.assertEqual(pow(pow(42, pub.e, pub.n), prv.d, pub.n), 42)


class DiscreteLogTest(unittest.TestCase):
    def test_elgamal(self):
        elgamal = cc.ElGamal(SecurityLevel.L0)
        elgamal.keygen()
        c1, c2 = elgamal.encrypt(MSG)
        self.assertEqual(elgamal.decrypt(c1, c2), MSG)
        r, s = elgamal.sign(MSG)
        self.assertTrue(elgamal.verify(MSG, r, s))
        self.assertFalse(elgamal.verify(MSG + b"!", r, s))
        with self.assertRaises(CryptoError):
            elgamal.decrypt(b"\x00", c2)
        with self.assertRaises(CryptoError):
            cc.ElGamal(SecurityLevel.L3)

    def test_dsa(self):
        for hash_function in (HashFunction.SHA2, HashFunction.SHA3):
            dsa = cc.DSA(SecurityLevel.L1, hash_function)
            dsa.keygen()
            r, s = dsa.sign(MSG)
            self.assertTrue(dsa.verify(MSG, r, s))
            self.assertFalse(dsa.verify(MSG, s, r))
        with self.assertRaises(CryptoError):
            cc.DSA(SecurityLevel.L0, HashFunction.MD5)

    def test_diffie_hellman(self):
        dh = cc.DiffieHellman(SecurityLevel.L0)
        a, b = dh.gen_secret(), dh.gen_secret()
        shared = dh.compute_shared_secret(a, dh.gen_public(b))
        self.assertEqual(shared, dh.compute_shared_secret(b, dh.gen_public(a)))
        with self.assertRaises(CryptoError):
            dh.compute_shared_secret(a, b"\x01")


class EllipticCurveTest(unittest.TestCase):
    SIGNING = [cc.Curve.P256, cc.Curve.SECP256K1, cc.Curve.P521, cc.Curve.ED25519, cc.Curve.ED448]
    MONTGOMERY = [cc.Curve.CURVE25519, cc.Curve.CURVE448]

    def test_ecelgamal(self):
        for curve in self.SIGNING + self.MONTGOMERY:
            with self.subTest(curve=curve):
                scheme = cc.ECElGamal(curve)
                scheme.keygen()
                message = b"\x00" + MSG
                c1, c2 = scheme.encrypt(message)
                self.assertEqual(scheme.decrypt(c1, c2), message)
                self.assertEqual(len(c1), len(scheme.pubKey.y))
                with self.assertRaises(CryptoError):
                    scheme.decrypt(b"\xff" * len(c1), c2)
                with self.assertRaises(CryptoError):
                    scheme.encrypt(b"a" * 100)
                if curve in self.MONTGOMERY:
                    with self.assertRaises(CryptoError):
                        scheme.sign(MSG)
                else:
                    r, s = scheme.sign(MSG)
                    self.assertTrue(scheme.verify(MSG, r, s))
                    self.assertFalse(scheme.verify(MSG + b"!", r, s))

    def test_ecdsa(self):
        for curve in self.SIGNING:
            with self.subTest(curve=curve):
                ecdsa = cc.ECDSA(curve, HashFunction.SHA3)
                ecdsa.keygen()
                r, s = ecdsa.sign(MSG)
                self.assertTrue(ecdsa.verify(MSG, r, s))
                self.assertFalse(ecdsa.verify(MSG + b"!", r, s))
        with self.assertRaises(CryptoError):
            cc.ECDSA(cc.Curve.CURVE25519)

    def test_ecdh(self):
        for curve in self.SIGNING + self.MONTGOMERY:
            with self.subTest(curve=curve):
                ecdh = cc.ECDH(curve)
                a, b = ecdh.gen_secret(), ecdh.gen_secret()
                public_b = ecdh.gen_public(b)
                shared = ecdh.compute_shared_secret(a, public_b)
                self.assertEqual(shared, ecdh.compute_shared_secret(b, ecdh.gen_public(a)))
                with self.assertRaises(CryptoError):
                    ecdh.compute_shared_secret(a, public_b + b"\x00")

    def test_curve_selection(self):
        ec = cc.EC(cc.ECType.EDWARDS, cc.EdwardsCurve.ED448)
        self.assertEqual(ec.curve, cc.Curve.ED448)
        with self.assertRaises(ValueError):
            cc.EC(cc.ECType.MONTGOMERY, cc.EdwardsCurve.ED448)
        scheme = cc.ECDSA(ec)
        scheme.keygen()
        self.assertEqual(str(scheme.pubKey.q), scheme.pubKey.q.hex())


if __name__ == "__main__":
    unittest.main()
