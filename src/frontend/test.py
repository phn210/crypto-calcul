from wrappers.enum import PrimalityTest, HashFunction, SecurityLevel # type: ignore
from wrappers.gmp import GMPInteger # type: ignore
from wrappers.rng import RNG # type: ignore
from wrappers.prime import Prime # type: ignore
from wrappers.sha3 import SHA3 # type: ignore
from wrappers.ec import P521, SECP256K1 # type: ignore
from wrappers.mac import HMAC # type: ignore
from wrappers.des import DES # type: ignore

rng = RNG()
base = 16
rand = rng.rand_int_b(1024, base)
modulo = GMPInteger()
modulo.set_value("971343446809354186848440295371971343446809354186848440295371", 10)
rand = rng.rand_int_m(modulo, base)

p = GMPInteger()
p.set_value("971343446809354186848440295371", 10)
prime = Prime()
prime.test(p, rng.state, 10, PrimalityTest.MILLER_RABIN_TEST)

message = "Hello, World!"
sha3_256 = SHA3(SecurityLevel.L3)

secp256k1 = SECP256K1()
p521 = P521()
p = p521.generator()
q = p521.point_from_bytes(bytes(p))
info = secp256k1.info()
p = secp256k1.generator()
p = p.dbl()
p = p * 2

hmac = HMAC(SecurityLevel.L1, HashFunction.SHA3)
keys = bytes('secret', 'utf-8')
data = bytes('Hello, HMAC!', 'utf-8')
mac = hmac.mac(keys, data)

des = DES()
keys = bytes.fromhex('133457799BBCDFF1')
data = bytes('Hello world!', 'utf-8')
encrypted = des.encrypt(data, keys)
decrypted = des.decrypt(encrypted, keys)

