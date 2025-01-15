from libc.stdlib cimport malloc, free

cdef extern from "aes.h":
    ctypedef enum AES_KEY_SIZE:
        AES_KEY_SIZE_128,
        AES_KEY_SIZE_192,
        AES_KEY_SIZE_256
    
    ctypedef enum AES_MODE:
        AES_MODE_ECB,
        AES_MODE_CBC,
        AES_MODE_CFB,
        AES_MODE_OFB,
        AES_MODE_CTR,
        AES_MODE_GCM

    cdef const size_t _AES_BLOCK_SIZE "AES_BLOCK_SIZE"

    void aes_encrypt_ecb(unsigned char *, unsigned char *, unsigned char *, size_t, AES_KEY_SIZE);
    void aes_decrypt_ecb(unsigned char *, unsigned char *, unsigned char *, size_t, AES_KEY_SIZE);

    void aes_encrypt_cbc(unsigned char *, unsigned char *, unsigned char *, unsigned char *, size_t, AES_KEY_SIZE);
    void aes_decrypt_cbc(unsigned char *, unsigned char *, unsigned char *, unsigned char *, size_t, AES_KEY_SIZE);

    void aes_encrypt_cfb(unsigned char *, unsigned char *, unsigned char *, unsigned char *, size_t, AES_KEY_SIZE);
    void aes_decrypt_cfb(unsigned char *, unsigned char *, unsigned char *, unsigned char *, size_t, AES_KEY_SIZE);

    void aes_encrypt_ofb(unsigned char *, unsigned char *, unsigned char *, unsigned char *, size_t, AES_KEY_SIZE);
    void aes_decrypt_ofb(unsigned char *, unsigned char *, unsigned char *, unsigned char *, size_t, AES_KEY_SIZE);

    void aes_ctr(unsigned char *input, unsigned char *output, unsigned char *nonce, unsigned char *key, size_t len, AES_KEY_SIZE key_size);

    void aes_file_encrypt(const char *, const char *, unsigned char *, unsigned char *, AES_KEY_SIZE, AES_MODE);
    void aes_file_decrypt(const char *, const char *, unsigned char *, unsigned char *, AES_KEY_SIZE, AES_MODE);

cdef extern from "conversion.h":
    unsigned char *pkcs7_padding(unsigned char *, size_t, size_t *, size_t)
    unsigned char *pkcs7_unpadding(unsigned char *, size_t, size_t *, size_t)

cdef class AES:
    cdef AES_KEY_SIZE key_size
    cdef AES_MODE mode
    
    cpdef bytes aes(self, bytes data, bytes key, bytes iv, bytes nonce, char f)
    cpdef bytes encrypt(self, bytes data, bytes key, bytes iv, bytes nonce)
    cpdef bytes decrypt(self, bytes data, bytes key, bytes iv, bytes nonce)
    cpdef void encrypt_file(self, str file_path, str output_path, bytes key, bytes iv)
    cpdef void decrypt_file(self, str file_path, str output_path, bytes key, bytes iv)
    cpdef bytes pad(self, bytes data, size_t length)
    cpdef bytes unpad(self, bytes padded_data, size_t length)
