#ifndef CRYPTOCALC_H
#define CRYPTOCALC_H

/*
 * crypto-calcul public API.
 *
 * Conventions
 *  - Every function returns a cc_status_t; CC_OK is 0. cc_strerror() describes a status.
 *  - Data crosses the API as bytes. Big integers (keys, signatures, primes) are big-endian.
 *  - Outputs are (uint8_t *out, size_t *out_len): *out_len holds the capacity of out on input
 *    and the number of bytes written on output. If out is NULL or too small, the call returns
 *    CC_ERR_BUFFER_TOO_SMALL and sets *out_len to the required size.
 *  - Verification functions return CC_OK for a valid signature or MAC and CC_ERR_VERIFY otherwise.
 *  - Contexts are created with cc_<scheme>_new() and released with cc_<scheme>_free(); they are
 *    not thread-safe, but separate contexts can be used from separate threads.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(_WIN32) && defined(CC_BUILDING_SHARED)
#define CC_API __declspec(dllexport)
#elif defined(_WIN32) && defined(CC_USING_SHARED)
#define CC_API __declspec(dllimport)
#elif defined(__GNUC__)
#define CC_API __attribute__((visibility("default")))
#else
#define CC_API
#endif

/* ------------------------------------------------------------------------- */
/* Status codes                                                              */
/* ------------------------------------------------------------------------- */

typedef enum cc_status
{
    CC_OK = 0,
    CC_ERR_INVALID_ARG,       // unknown security level, hash function, curve, mode, key size...
    CC_ERR_UNSUPPORTED,       // valid combination that the library does not implement
    CC_ERR_NOMEM,             // memory allocation failed
    CC_ERR_IO,                // file could not be opened, read or written
    CC_ERR_RNG,               // the system random source could not be read
    CC_ERR_INVALID_INPUT,     // malformed or out-of-range input data
    CC_ERR_MSG_TOO_LONG,      // message too long for the key or scheme
    CC_ERR_DECRYPT,           // decryption failed (invalid padding, wrong key or corrupted ciphertext)
    CC_ERR_VERIFY,            // signature or MAC does not verify
    CC_ERR_BUFFER_TOO_SMALL,  // output buffer too small; the required size is returned
    CC_ERR_NO_KEY,            // the operation needs a key that has not been generated or set
} cc_status_t;

CC_API const char *cc_strerror(cc_status_t status);

/* ------------------------------------------------------------------------- */
/* Parameters                                                                */
/* ------------------------------------------------------------------------- */

// Security level in bits. Not every scheme supports every level (CC_ERR_INVALID_ARG).
typedef enum cc_sec_level
{
    CC_SEC_112 = 112,
    CC_SEC_128 = 128,
    CC_SEC_192 = 192,
    CC_SEC_256 = 256,
} cc_sec_level_t;

// Hash family; for SHA-2 and SHA-3 the output size follows the security level (224 to 512 bits)
typedef enum cc_hash
{
    CC_HASH_MD5,
    CC_HASH_SHA1,
    CC_HASH_SHA2,
    CC_HASH_SHA3,
} cc_hash_t;

typedef enum cc_curve
{
    // Short Weierstrass
    CC_CURVE_P224,
    CC_CURVE_P256,
    CC_CURVE_P384,
    CC_CURVE_P521,
    CC_CURVE_SECP256K1,
    CC_CURVE_W25519,
    CC_CURVE_W448,
    // Montgomery (x-only: no signatures)
    CC_CURVE_25519,
    CC_CURVE_448,
    // Twisted Edwards
    CC_CURVE_ED25519,
    CC_CURVE_ED448,
    CC_CURVE_E448,
} cc_curve_t;

/* ------------------------------------------------------------------------- */
/* Hash functions                                                            */
/* ------------------------------------------------------------------------- */

// digest_len: 16 (MD5), 20 (SHA-1), 28/32/48/64 (SHA-2, SHA-3) bytes depending on the level
CC_API cc_status_t cc_hash(cc_hash_t hash, cc_sec_level_t level, const uint8_t *msg, size_t msg_len,
                           uint8_t *digest, size_t *digest_len);
// SHAKE128 (security_bits = 128) or SHAKE256 (256), producing out_len bytes
CC_API cc_status_t cc_shake(int security_bits, const uint8_t *msg, size_t msg_len, uint8_t *out, size_t out_len);

/* ------------------------------------------------------------------------- */
/* Random numbers and primes                                                 */
/* ------------------------------------------------------------------------- */

typedef enum cc_prime_test
{
    CC_PRIME_TEST_GMP,
    CC_PRIME_TEST_FERMAT,
    CC_PRIME_TEST_MILLER_RABIN,
} cc_prime_test_t;

CC_API cc_status_t cc_random_bytes(uint8_t *out, size_t len);
// Uniform integer in [0, 2^bits)
CC_API cc_status_t cc_random_bits(unsigned int bits, uint8_t *out, size_t *out_len);
// Uniform integer in [0, m); m > 0
CC_API cc_status_t cc_random_below(const uint8_t *m, size_t m_len, uint8_t *out, size_t *out_len);

// Sets *is_prime to 1 if n is (probably) prime after `rounds` rounds of the test, 0 otherwise
CC_API cc_status_t cc_is_prime(const uint8_t *n, size_t n_len, cc_prime_test_t test, int rounds, int *is_prime);
// Random prime of `bits` bits; `small_primes` primes are used for trial division first
CC_API cc_status_t cc_prime_bits(unsigned int bits, int small_primes, cc_prime_test_t test, int rounds,
                                 uint8_t *out, size_t *out_len);
// Random prime below m (m > 2)
CC_API cc_status_t cc_prime_below(const uint8_t *m, size_t m_len, int small_primes, cc_prime_test_t test, int rounds,
                                  uint8_t *out, size_t *out_len);

/* ------------------------------------------------------------------------- */
/* Symmetric encryption (PKCS#7 padding)                                     */
/* ------------------------------------------------------------------------- */

typedef enum cc_aes_mode
{
    CC_AES_ECB,
    CC_AES_CBC,
    CC_AES_CFB,
    CC_AES_OFB,
    CC_AES_CTR,
} cc_aes_mode_t;

// key_len is 16, 24 or 32 bytes; iv is 16 bytes (the nonce in CTR mode, ignored in ECB mode).
// Ciphertexts are a multiple of 16 bytes and at most 16 bytes longer than the plaintext.
CC_API cc_status_t cc_aes_encrypt(cc_aes_mode_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv,
                                  const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
CC_API cc_status_t cc_aes_decrypt(cc_aes_mode_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv,
                                  const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
CC_API cc_status_t cc_aes_encrypt_file(cc_aes_mode_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv,
                                       const char *in_path, const char *out_path);
CC_API cc_status_t cc_aes_decrypt_file(cc_aes_mode_t mode, const uint8_t *key, size_t key_len, const uint8_t *iv,
                                       const char *in_path, const char *out_path);

// DES-ECB with an 8-byte big-endian key; blocks are big-endian as in FIPS 46-3
CC_API cc_status_t cc_des_encrypt(const uint8_t key[8], const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
CC_API cc_status_t cc_des_decrypt(const uint8_t key[8], const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
CC_API cc_status_t cc_des_encrypt_file(const uint8_t key[8], const char *in_path, const char *out_path);
CC_API cc_status_t cc_des_decrypt_file(const uint8_t key[8], const char *in_path, const char *out_path);

/* ------------------------------------------------------------------------- */
/* Message authentication codes                                              */
/* ------------------------------------------------------------------------- */

CC_API cc_status_t cc_hmac(cc_hash_t hash, cc_sec_level_t level, const uint8_t *key, size_t key_len,
                           const uint8_t *msg, size_t msg_len, uint8_t *mac, size_t *mac_len);
CC_API cc_status_t cc_hmac_verify(cc_hash_t hash, cc_sec_level_t level, const uint8_t *key, size_t key_len,
                                  const uint8_t *msg, size_t msg_len, const uint8_t *mac, size_t mac_len);
CC_API cc_status_t cc_hmac_file(cc_hash_t hash, cc_sec_level_t level, const uint8_t *key, size_t key_len,
                                const char *path, uint8_t *mac, size_t *mac_len);

// AES-CBC-MAC with a 16-byte tag; levels 128, 192 and 256 select the AES key size
CC_API cc_status_t cc_cbc_mac(cc_sec_level_t level, const uint8_t *key, size_t key_len,
                              const uint8_t *msg, size_t msg_len, uint8_t *mac, size_t *mac_len);
CC_API cc_status_t cc_cbc_mac_verify(cc_sec_level_t level, const uint8_t *key, size_t key_len,
                                     const uint8_t *msg, size_t msg_len, const uint8_t *mac, size_t mac_len);
CC_API cc_status_t cc_cbc_mac_file(cc_sec_level_t level, const uint8_t *key, size_t key_len,
                                   const char *path, uint8_t *mac, size_t *mac_len);

/* ------------------------------------------------------------------------- */
/* RSA                                                                       */
/* ------------------------------------------------------------------------- */

typedef struct cc_rsa cc_rsa_t;

typedef enum cc_rsa_scheme
{
    CC_RSA_TEXTBOOK, // raw RSA on the message read as a big-endian integer
    CC_RSA_PKCS1,    // PKCS#1 v1.5 encryption and signatures
    CC_RSA_OAEP_PSS, // OAEP encryption and PSS signatures
} cc_rsa_scheme_t;

typedef enum cc_rsa_param
{
    CC_RSA_N,
    CC_RSA_E,
    CC_RSA_D,
    CC_RSA_P,
    CC_RSA_Q,
    CC_RSA_DP,
    CC_RSA_DQ,
    CC_RSA_QINV,
} cc_rsa_param_t;

// Levels 112, 128, 192 and 256 give 2048, 3072, 7680 and 15360-bit moduli
CC_API cc_status_t cc_rsa_new(cc_rsa_t **ctx, cc_sec_level_t level, cc_rsa_scheme_t scheme);
CC_API void cc_rsa_free(cc_rsa_t *ctx);
CC_API cc_status_t cc_rsa_keygen(cc_rsa_t *ctx);
// Private-key operations use the Chinese Remainder Theorem unless disabled (enabled by default)
CC_API cc_status_t cc_rsa_use_crt(cc_rsa_t *ctx, int use_crt);
// Size of the modulus in bytes: the length of ciphertexts and signatures of the padded schemes
CC_API cc_status_t cc_rsa_size(const cc_rsa_t *ctx, size_t *size);
CC_API cc_status_t cc_rsa_get(const cc_rsa_t *ctx, cc_rsa_param_t param, uint8_t *out, size_t *out_len);

CC_API cc_status_t cc_rsa_encrypt(cc_rsa_t *ctx, const uint8_t *msg, size_t msg_len, uint8_t *out, size_t *out_len);
CC_API cc_status_t cc_rsa_decrypt(cc_rsa_t *ctx, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
CC_API cc_status_t cc_rsa_sign(cc_rsa_t *ctx, const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len);
CC_API cc_status_t cc_rsa_verify(cc_rsa_t *ctx, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

/* ------------------------------------------------------------------------- */
/* ElGamal and DSA (finite fields)                                           */
/* ------------------------------------------------------------------------- */

typedef struct cc_elgamal cc_elgamal_t;
typedef struct cc_dsa cc_dsa_t;

typedef enum cc_dl_param
{
    CC_DL_P, // group modulus
    CC_DL_Q, // subgroup order (DSA only)
    CC_DL_G, // generator
    CC_DL_X, // private key
    CC_DL_Y, // public key g^x mod p
} cc_dl_param_t;

// ElGamal supports levels 112 and 128 (RFC 3526 groups); signatures hash with SHA-2
CC_API cc_status_t cc_elgamal_new(cc_elgamal_t **ctx, cc_sec_level_t level);
CC_API void cc_elgamal_free(cc_elgamal_t *ctx);
CC_API cc_status_t cc_elgamal_keygen(cc_elgamal_t *ctx);
CC_API cc_status_t cc_elgamal_get(const cc_elgamal_t *ctx, cc_dl_param_t param, uint8_t *out, size_t *out_len);
// Multiplicative ElGamal: the message is read as a big-endian integer below p
CC_API cc_status_t cc_elgamal_encrypt(cc_elgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                                      uint8_t *c1, size_t *c1_len, uint8_t *c2, size_t *c2_len);
CC_API cc_status_t cc_elgamal_decrypt(cc_elgamal_t *ctx, const uint8_t *c1, size_t c1_len, const uint8_t *c2, size_t c2_len,
                                      uint8_t *out, size_t *out_len);
CC_API cc_status_t cc_elgamal_sign(cc_elgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                                   uint8_t *r, size_t *r_len, uint8_t *s, size_t *s_len);
CC_API cc_status_t cc_elgamal_verify(cc_elgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                                     const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len);

// DSA supports levels 112 and 128 (FIPS 186 groups) with SHA-2 or SHA-3
CC_API cc_status_t cc_dsa_new(cc_dsa_t **ctx, cc_sec_level_t level, cc_hash_t hash);
CC_API void cc_dsa_free(cc_dsa_t *ctx);
CC_API cc_status_t cc_dsa_keygen(cc_dsa_t *ctx);
CC_API cc_status_t cc_dsa_get(const cc_dsa_t *ctx, cc_dl_param_t param, uint8_t *out, size_t *out_len);
CC_API cc_status_t cc_dsa_sign(cc_dsa_t *ctx, const uint8_t *msg, size_t msg_len,
                               uint8_t *r, size_t *r_len, uint8_t *s, size_t *s_len);
CC_API cc_status_t cc_dsa_verify(cc_dsa_t *ctx, const uint8_t *msg, size_t msg_len,
                                 const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len);

// Diffie-Hellman over the ElGamal groups (levels 112 and 128)
CC_API cc_status_t cc_dh_generate_secret(cc_sec_level_t level, uint8_t *secret, size_t *secret_len);
CC_API cc_status_t cc_dh_public(cc_sec_level_t level, const uint8_t *secret, size_t secret_len,
                                uint8_t *pub, size_t *pub_len);
CC_API cc_status_t cc_dh_shared_secret(cc_sec_level_t level, const uint8_t *secret, size_t secret_len,
                                       const uint8_t *peer_pub, size_t peer_pub_len, uint8_t *shared, size_t *shared_len);

/* ------------------------------------------------------------------------- */
/* Elliptic curves                                                           */
/* ------------------------------------------------------------------------- */

typedef struct cc_ecelgamal cc_ecelgamal_t;
typedef struct cc_ecdsa cc_ecdsa_t;

typedef enum cc_ec_param
{
    CC_EC_PRIVATE, // private scalar
    CC_EC_PUBLIC,  // public point: x || y, or x alone on Montgomery curves, each coordinate field-sized
} cc_ec_param_t;

// hash is CC_HASH_SHA2 or CC_HASH_SHA3; the output size follows the curve
CC_API cc_status_t cc_ecelgamal_new(cc_ecelgamal_t **ctx, cc_curve_t curve, cc_hash_t hash);
CC_API void cc_ecelgamal_free(cc_ecelgamal_t *ctx);
CC_API cc_status_t cc_ecelgamal_keygen(cc_ecelgamal_t *ctx);
CC_API cc_status_t cc_ecelgamal_get(const cc_ecelgamal_t *ctx, cc_ec_param_t param, uint8_t *out, size_t *out_len);
// Hashed EC-ElGamal: c1 is a point, c2 = msg XOR H(shared point). Messages are at most the hash size.
CC_API cc_status_t cc_ecelgamal_encrypt(cc_ecelgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                                        uint8_t *c1, size_t *c1_len, uint8_t *c2, size_t *c2_len);
CC_API cc_status_t cc_ecelgamal_decrypt(cc_ecelgamal_t *ctx, const uint8_t *c1, size_t c1_len, const uint8_t *c2, size_t c2_len,
                                        uint8_t *out, size_t *out_len);
// Signatures need point addition: not available on Montgomery curves (CC_ERR_UNSUPPORTED)
CC_API cc_status_t cc_ecelgamal_sign(cc_ecelgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                                     uint8_t *r, size_t *r_len, uint8_t *s, size_t *s_len);
CC_API cc_status_t cc_ecelgamal_verify(cc_ecelgamal_t *ctx, const uint8_t *msg, size_t msg_len,
                                       const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len);

// ECDSA is not available on Montgomery curves (CC_ERR_UNSUPPORTED)
CC_API cc_status_t cc_ecdsa_new(cc_ecdsa_t **ctx, cc_curve_t curve, cc_hash_t hash);
CC_API void cc_ecdsa_free(cc_ecdsa_t *ctx);
CC_API cc_status_t cc_ecdsa_keygen(cc_ecdsa_t *ctx);
CC_API cc_status_t cc_ecdsa_get(const cc_ecdsa_t *ctx, cc_ec_param_t param, uint8_t *out, size_t *out_len);
CC_API cc_status_t cc_ecdsa_sign(cc_ecdsa_t *ctx, const uint8_t *msg, size_t msg_len,
                                 uint8_t *r, size_t *r_len, uint8_t *s, size_t *s_len);
CC_API cc_status_t cc_ecdsa_verify(cc_ecdsa_t *ctx, const uint8_t *msg, size_t msg_len,
                                   const uint8_t *r, size_t r_len, const uint8_t *s, size_t s_len);

// ECDH: public values are encoded points (see CC_EC_PUBLIC); the peer's point is validated
CC_API cc_status_t cc_ecdh_generate_secret(cc_curve_t curve, uint8_t *secret, size_t *secret_len);
CC_API cc_status_t cc_ecdh_public(cc_curve_t curve, const uint8_t *secret, size_t secret_len,
                                  uint8_t *pub, size_t *pub_len);
CC_API cc_status_t cc_ecdh_shared_secret(cc_curve_t curve, const uint8_t *secret, size_t secret_len,
                                         const uint8_t *peer_pub, size_t peer_pub_len, uint8_t *shared, size_t *shared_len);

#ifdef __cplusplus
}
#endif

#endif
