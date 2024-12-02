from wrappers.enum import SecurityLevel # type: ignore
from wrappers.rng import RNG # type: ignore
from wrappers.sha3 import SHA3, SHAKE # type: ignore

rng = RNG()
base = 16
rand = rng.rand_int_b(1024, base)
print(rand)
print(int(rand, base))

message = "Hello, World!"
sha3_256 = SHA3(SecurityLevel._L3.value)
print(sha3_256.hash(message.encode('utf-8')).hex())