from wrappers.enums import PrimalityTest, HashFunction, SecurityLevel
from wrappers.gmp import GMPInteger
from wrappers.rng import RNG
from wrappers.prime import Prime
from wrappers.md5 import MD5
from wrappers.sha1 import SHA1
from wrappers.sha2 import SHA256
from wrappers.sha3 import SHA3_512, SHAKE256
from wrappers.ec import P521, SECP256K1
from wrappers.mac import HMAC, CBCMAC
from wrappers.des import DES
from wrappers.aes import AES_128_CBC

rng = RNG()
base = 10
rand = rng.rand_int_b(1024, base)
modulo = GMPInteger()
modulo.set_value("971343446809354186848440295371971343446809354186848440295371", 10)
rand = rng.rand_int_m(modulo, base)

p = GMPInteger()
p.set_value("971343446809354186848440295371", 10)
prime = Prime()
prime.test(p, rng.state, 10, PrimalityTest.MILLER_RABIN_TEST)

message = "Hello, World!"
md5 = MD5()
sha1 = SHA1()
sha256 = SHA256()
sha3_512 = SHA3_512()
shake256 = SHAKE256()
digest = md5.hash(bytes(message, 'utf-8'))
digest = sha1.hash(bytes(message, 'utf-8'))
digest = sha256.hash(bytes(message, 'utf-8'))
digest = sha3_512.hash(bytes(message, 'utf-8'))
shake256.update(bytes(message, 'utf-8'))
shake256.xof()
digest = shake256.squeeze(100)

secp256k1 = SECP256K1()
p521 = P521()
P = p521.generator()
Q = p521.point_from_bytes(bytes(P))
info = secp256k1.info()
P = secp256k1.generator()
P = P.dbl()
P = P * 2

hmac = HMAC(SecurityLevel.L1, HashFunction.SHA3)
cbcmac = CBCMAC(SecurityLevel.L1)
keys = bytes('secret', 'utf-8')
data = bytes('Hello, HMAC!', 'utf-8')
mac = hmac.mac(keys, data)
mac = cbcmac.mac(keys, data)

des = DES()
keys = bytes.fromhex('133457799BBCDFF1')
data = bytes('Hello world!', 'utf-8')
encrypted = des.encrypt(data, keys)
decrypted = des.decrypt(encrypted, keys)
# File path might need to be changed
des.encrypt_file('src/frontend/test/input.txt', 'src/frontend/test/des_output_enc.txt', keys)
des.decrypt_file('src/frontend/test/des_output_enc.txt', 'src/frontend/test/des_output_dec.txt', keys)

aes_128_cbc = AES_128_CBC()
keys = bytes.fromhex("133457799BBCDFF1133457799BBCDFF1")
iv = bytes(bytearray([10]*16))
data = bytes('Hello world! My name is John Doe.', 'utf-8')
nonce = bytes('nonce value', 'utf-8')
encrypted = aes_128_cbc.encrypt(data, keys, iv, b'')
decrypted = aes_128_cbc.decrypt(encrypted, keys, iv, b'')
# File path might need to be changed
aes_128_cbc.encrypt_file('src/frontend/test/input.txt', 'src/frontend/test/aes_output_enc.txt', keys, iv)
aes_128_cbc.decrypt_file('src/frontend/test/aes_output_enc.txt', 'src/frontend/test/aes_output_dec.txt', keys, iv)