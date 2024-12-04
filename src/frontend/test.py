import pyximport; pyximport.install()
from wrappers.enum import SecurityLevel # type: ignore
from wrappers.rng import RNG # type: ignore
from wrappers.sha3 import SHA3 # type: ignore
from wrappers.ec import P256, P384, P521, SECP256K1 # type: ignore

rng = RNG()
base = 16
rand = rng.rand_int_b(1024, base)
print(rand)
print(int(rand, base))

message = "Hello, World!"
sha3_256 = SHA3(SecurityLevel.L3)
print(sha3_256.hash(message.encode('utf-8')).hex())

secp256k1 = SECP256K1()
p521 = P521()
p = p521.generator()
q = p521.point_from_bytes(bytes(p))
print(p == q)
info = secp256k1.info()
p = secp256k1.generator()
print(secp256k1 == secp256k1)
print(p.is_on_curve())
print(p == p)
p = p.dbl()
print(p.is_on_curve())
p = p * 2
print(p.is_on_curve())
print(secp256k1.is_infinity(secp256k1.infinity()))