from utils import add_build_to_path
add_build_to_path()

from wrappers.enums import HashFunction, SecurityLevel
from wrappers.gmp import GMPInteger
from wrappers.rng import RNG
from wrappers.prime import Prime, PrimalityTest
from wrappers.md5 import MD5
from wrappers.sha1 import SHA1
from wrappers.sha2 import SHA256
from wrappers.sha3 import SHA3_512, SHAKE256
from wrappers.ec import P521, SECP256K1
from wrappers.mac import HMAC, CBCMAC
from wrappers.des import DES
from wrappers.aes import AES_128_CBC
from wrappers.rsa import RSA, RSAAlgo, RSAVariant
from wrappers.elgamal import ElGamal
from wrappers.ecelgamal import ECElGamal
from wrappers.dsa import DSA
from wrappers.ecdsa import ECDSA
from wrappers.dh import DiffieHellman
from wrappers.ecdh import ECDH

# Path might need to be changed
RELATIVE_TEST_DIR = 'src/frontend/test'

rng = RNG()
base = 10
rand = rng.rand_int_b(1024, base)
modulo = GMPInteger()
modulo.set_value("971343446809354186848440295371971343446809354186848440295371", 10)
rand = rng.rand_int_m(modulo, base)

p = GMPInteger()
p.set_value("971343446809354186848440295371", 10)
prime = Prime()
prime.test(p, rng.state, 10, PrimalityTest.MILLER_RABIN)

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
hmac.verify(keys, data, mac)
mac = hmac.mac_file(f'{RELATIVE_TEST_DIR}/input.txt', keys)
hmac.verify_file(f'{RELATIVE_TEST_DIR}/input.txt', keys, mac)
mac = cbcmac.mac(keys, data)
cbcmac.verify(keys, data, mac)
mac = cbcmac.mac_file(f'{RELATIVE_TEST_DIR}/input.txt', keys)
cbcmac.verify_file(f'{RELATIVE_TEST_DIR}/input.txt', keys, mac)

des = DES()
keys = bytes.fromhex('133457799BBCDFF1')
data = bytes('Hello world!', 'utf-8')
encrypted = des.encrypt(data, keys)
decrypted = des.decrypt(encrypted, keys)
des.encrypt_file(f'{RELATIVE_TEST_DIR}/input.txt', f'{RELATIVE_TEST_DIR}/des_output_enc.txt', keys)
des.decrypt_file(f'{RELATIVE_TEST_DIR}/des_output_enc.txt', f'{RELATIVE_TEST_DIR}/des_output_dec.txt', keys)

aes_128_cbc = AES_128_CBC()
keys = bytes.fromhex("133457799BBCDFF1133457799BBCDFF1")
iv = bytes(bytearray([10]*16))
data = bytes('Hello world! My name is John Doe.', 'utf-8')
nonce = bytes('nonce value', 'utf-8')
encrypted = aes_128_cbc.encrypt(data, keys, iv, b'')
decrypted = aes_128_cbc.decrypt(encrypted, keys, iv, b'')
aes_128_cbc.encrypt_file(f'{RELATIVE_TEST_DIR}/input.txt', f'{RELATIVE_TEST_DIR}/aes_output_enc.txt', keys, iv)
aes_128_cbc.decrypt_file(f'{RELATIVE_TEST_DIR}/aes_output_enc.txt', f'{RELATIVE_TEST_DIR}/aes_output_dec.txt', keys, iv)

rsa = RSA(SecurityLevel.L1, RSAVariant.PKCS1)
rsa.keygen()
message = bytes('Hello, RSA!', 'utf-8')
encrypted = rsa.encrypt(message)
decrypted = rsa.decrypt(encrypted, RSAAlgo.STANDARD)
signed_message = rsa.sign(message, RSAAlgo.STANDARD)
verified = rsa.verify(message, signed_message)

elgamal = ElGamal(SecurityLevel.L1)
elgamal.keygen()
message = bytes('Hello, ElGamal!', 'utf-8')
encrypted = elgamal.encrypt(message)
decrypted = elgamal.decrypt(encrypted[0], encrypted[1])
signed_message = elgamal.sign(message)
verified = elgamal.verify(message, signed_message[0], signed_message[1])

ecelgamal = ECElGamal(secp256k1)
ecelgamal.keygen()
message = bytes('Hello, ECElGamal!', 'utf-8')
encrypted = ecelgamal.encrypt(message, HashFunction.SHA2)
decrypted = ecelgamal.decrypt(encrypted[0], encrypted[1], HashFunction.SHA2)
signed_message = ecelgamal.sign(message, HashFunction.SHA2)
verified = ecelgamal.verify(message, signed_message[0], signed_message[1], HashFunction.SHA2)

dsa = DSA(SecurityLevel.L1, HashFunction.SHA2)
dsa.keygen()
message = bytes('Hello, DSA!', 'utf-8')
signature = dsa.sign(message)
verified = dsa.verify(message, signature[0], signature[1])

ecdsa = ECDSA(secp256k1)
ecdsa.keygen()
message = bytes('Hello, ECDSA!', 'utf-8')
signature = ecdsa.sign(message, HashFunction.SHA2)
verified = ecdsa.verify(message, signature[0], signature[1], HashFunction.SHA2)

dh = DiffieHellman(SecurityLevel.L1)
secret_A = dh.gen_secret()
public_A = dh.gen_public(secret_A)
secret_B = dh.gen_secret()
public_B = dh.gen_public(secret_B)
shared_secret_A = dh.compute_shared_secret(secret_A, public_B)
shared_secret_B = dh.compute_shared_secret(secret_B, public_A)

ecdh = ECDH(secp256k1)
secret_A = ecdh.gen_secret()
public_A = ecdh.gen_public(secret_A)
secret_B = ecdh.gen_secret()
public_B = ecdh.gen_public(secret_B)
shared_secret_A = ecdh.compute_shared_secret(secret_A, public_B)
shared_secret_B = ecdh.compute_shared_secret(secret_B, public_A)
print("Done!")