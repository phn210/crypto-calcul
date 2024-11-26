#include "conversion.h"
#include "elgamal.h"
#include "prime_gen.h"
#include "rng.h"

#define L0_P_BITS 2048
#define L0_P "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
#define L0_G "02"

#define L1_P_BITS 3072
#define L1_P "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
#define L1_G "02"

void setup(public_params_t *pp, SECURITY_LEVEL level)
{
    mpz_inits(pp->p, pp->g, NULL);

    switch (level)
    {
    case L0:
        pp->p_bits = L0_P_BITS;
        hex_to_bigint(pp->p, L0_P);
        hex_to_bigint(pp->g, "02");
        break;
    // case L2:
    //     pp->p_bits = 7680;
    //     hex_to_bigint(pp->p, P);
    //     hex_to_bigint(pp->g, G);
    //     break;
    // case L3:
    //     pp->p_bits = 15360;
    //     hex_to_bigint(pp->p, P);
    //     hex_to_bigint(pp->g, G);
    //     break;
    default: // L1
        pp->p_bits = L1_P_BITS;
        hex_to_bigint(pp->p, L1_P);
        hex_to_bigint(pp->g, L1_G);
        break;
    }
}

void keygen(priv_key_t *sk, pub_key_t *pk, const public_params_t pp)
{
    mpz_inits(sk->x, pk->y, NULL);

    gmp_randstate_t state;
    rng_init(state);
    rand_int_m(sk->x, state, pp.p);

    mpz_powm(pk->y, pp.g, sk->x, pp.p);
}

void encrypt(mpz_t c1, mpz_t c2, const mpz_t m, const pub_key_t pk, const public_params_t pp)
{
    mpz_t k;
    mpz_inits(k, c1, c2, NULL);

    gmp_randstate_t state;
    rng_init(state);
    rand_int_m(k, state, pp.p);
    mpz_powm(c1, pp.g, k, pp.p);
    mpz_powm(c2, pk.y, k, pp.p);
    mpz_mul(c2, c2, m);
    mpz_mod(c2, c2, pp.p);

    mpz_clear(k);
}

void decrypt(mpz_t m, const mpz_t c1, const mpz_t c2, const priv_key_t sk, const public_params_t pp)
{
    mpz_t s;
    mpz_init(s);

    mpz_powm(s, c1, sk.x, pp.p);
    mpz_invert(s, s, pp.p);
    mpz_mul(m, c2, s);
    mpz_mod(m, m, pp.p);

    mpz_clear(s);
}