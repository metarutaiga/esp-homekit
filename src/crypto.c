#include <string.h>

#ifdef USE_WOLFSSL
// #include "user_settings.h"
// #include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/srp.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#else
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#include <stdio.h>
#include <errno.h>
#include <crypto/tls/bignum.h>
#include <libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h>
#include <libsodium/src/libsodium/include/sodium/crypto_kdf_hkdf_sha512.h>
#include <libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h>
#include <libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h>
#include <libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h>
#define CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE crypto_aead_chacha20poly1305_ietf_ABYTES
#define SRP_MODULUS_MIN_BITS 512
#define SRP_PRIVATE_KEY_MIN_BITS 256
typedef struct _Srp {
    struct crypto_hash_sha512_state client_proof;
    struct crypto_hash_sha512_state server_proof;
    struct bignum                  *N;
    struct bignum                  *g;
    struct bignum                  *auth;
    struct bignum                  *priv;
    uint8_t                         k[crypto_hash_sha512_BYTES];
    uint8_t                        *key;
    uint32_t                        keySz;
    uint8_t                        *salt;
    uint32_t                        saltSz;
} Srp;
#include "crypto.h"
#endif

#include "port.h"
#include "debug.h"


// 3072-bit group N (per RFC5054, Appendix A)
const byte N[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
  0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
  0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
  0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
  0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
  0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
  0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
  0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
  0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
  0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
  0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
  0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
  0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
  0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
  0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
  0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
  0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
  0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
  0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
  0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
  0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d,
  0x04, 0x50, 0x7a, 0x33, 0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64,
  0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a, 0x8a, 0xea, 0x71, 0x57,
  0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
  0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0,
  0x4a, 0x25, 0x61, 0x9d, 0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b,
  0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64, 0xd8, 0x76, 0x02, 0x73,
  0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
  0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0,
  0xba, 0xd9, 0x46, 0xe2, 0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31,
  0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e, 0x4b, 0x82, 0xd1, 0x20,
  0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

// 3072-bit group generator (per RFC5054, Appendix A)
const byte g[] = {0x05};


#ifdef USE_WOLFSSL
int wc_SrpSetKeyH(Srp *srp, byte *secret, word32 size) {
    SrpHash hash;
    int r = BAD_FUNC_ARG;

    srp->key = (byte*) XMALLOC(WC_SHA512_DIGEST_SIZE, NULL, DYNAMIC_TYPE_SRP);
    if (!srp->key)
        return MEMORY_E;

    srp->keySz = WC_SHA512_DIGEST_SIZE;

    r = wc_InitSha512(&hash.data.sha512);
    if (!r) r = wc_Sha512Update(&hash.data.sha512, secret, size);
    if (!r) r = wc_Sha512Final(&hash.data.sha512, srp->key);
#else
int crypto_srp_key(Srp *srp, u8 *secret, u32 size) {
    struct crypto_hash_sha512_state hash;
    int r = 0;

    srp->key = malloc(crypto_hash_sha512_BYTES);
    if (!srp->key)
        return ENOMEM;

    srp->keySz = crypto_hash_sha512_BYTES;

            r = crypto_hash_sha512_init(&hash);
    if (!r) r = crypto_hash_sha512_update(&hash, secret, size);
    if (!r) r = crypto_hash_sha512_final(&hash, srp->key);
#endif
    // clean up hash data from stack for security
    memset(&hash, 0, sizeof(hash));

    return r;
}


Srp *crypto_srp_new() {
    Srp *srp = malloc(sizeof(Srp));

    DEBUG("Initializing SRP");
#ifdef USE_WOLFSSL
    int r = wc_SrpInit(srp, SRP_TYPE_SHA512, SRP_CLIENT_SIDE);
    if (r) {
        DEBUG("Failed to initialize SRP (code %d)", r);
        return NULL;
    }
    srp->keyGenFunc_cb = wc_SrpSetKeyH;
#else
    crypto_hash_sha512_init(&srp->client_proof);
    crypto_hash_sha512_init(&srp->server_proof);
    srp->N = bignum_init();
    srp->g = bignum_init();
    srp->auth = bignum_init();
    srp->priv = bignum_init();
    srp->key = NULL;
    srp->keySz = 0;
    srp->salt = NULL;
    srp->saltSz = 0;
    if (srp->N == NULL || srp->g == NULL || srp->auth == NULL || srp->priv == NULL) {
        bignum_deinit(srp->N);
        bignum_deinit(srp->g);
        bignum_deinit(srp->auth);
        bignum_deinit(srp->priv);
        free(srp);
        DEBUG("Failed to initialize SRP (code %d)", ENOMEM);
        return NULL;
    }
#endif
    return srp;
}


void crypto_srp_free(Srp *srp) {
#ifdef USE_WOLFSSL
    wc_SrpTerm(srp);
#else
    if (srp) {
        bignum_deinit(srp->N);
        bignum_deinit(srp->g);
        bignum_deinit(srp->auth);
        bignum_deinit(srp->priv);
        free(srp->key);
        free(srp->salt);
    }
#endif
    free(srp);
}


int crypto_srp_init(Srp *srp, const char *username, const char *password) {
    DEBUG("Generating salt");
    byte salt[16];
    homekit_random_fill(salt, sizeof(salt));
#ifdef USE_WOLFSSL
    int r;
    DEBUG("Setting SRP username");
    r = wc_SrpSetUsername(srp, (byte*)username, strlen(username));
    if (r) {
        DEBUG("Failed to set SRP username (code %d)", r);
        return r;
    }

    DEBUG("Setting SRP params");
    r = wc_SrpSetParams(srp, N, sizeof(N), g, sizeof(g), salt, sizeof(salt));
    if (r) {
        DEBUG("Failed to set SRP params (code %d)", r);
        return r;
    }

    DEBUG("Setting SRP password");
    r = wc_SrpSetPassword(srp, (byte *)password, strlen(password));
    if (r) {
        DEBUG("Failed to set SRP password (code %d)", r);
        return r;
    }

    DEBUG("Getting SRP verifier");
    word32 verifierLen = 1024;
    byte *verifier = malloc(verifierLen);
    r = wc_SrpGetVerifier(srp, verifier, &verifierLen);
    if (r) {
        DEBUG("Failed to get SRP verifier (code %d)", r);
        free(verifier);
        return r;
    }

    srp->side = SRP_SERVER_SIDE;
    DEBUG("Setting SRP verifier");
    r = wc_SrpSetVerifier(srp, verifier, verifierLen);
    if (r) {
        DEBUG("Failed to set SRP verifier (code %d)", r);
        free(verifier);
        return r;
    }

    free(verifier);
#else
    struct crypto_hash_sha512_state hash;
    byte digest1[crypto_hash_sha512_BYTES];
    byte digest2[crypto_hash_sha512_BYTES];
    byte pad = 0;
    int i = 0;
    int j = 0;
    int r = 0;

    DEBUG("Setting SRP params");

    /* Set N */
    if (bignum_set_unsigned_bin(srp->N, N, sizeof(N)) != 0)
        return EINVAL;

//  if (bignum_get_unsigned_bin_len(srp->N) < SRP_MODULUS_MIN_BITS)
//      return EINVAL;

    /* Set g */
    if (bignum_set_unsigned_bin(srp->g, g, sizeof(g)) != 0)
        return EINVAL;

//  if (bignum_cmp(srp->N, srp->g) != 1)
//      return EINVAL;

    /* Set salt */
    srp->salt = malloc(sizeof(salt));
    if (srp->salt == NULL)
        return ENOMEM;

    memcpy(srp->salt, salt, sizeof(salt));
    srp->saltSz = sizeof(salt);

    DEBUG("Setting SRP username");

    /* Set k = H(N, g) */
            r = crypto_hash_sha512_init(&hash);
    if (!r) r = crypto_hash_sha512_update(&hash, N, sizeof(N));
    for (i = 0; i < sizeof(N) - sizeof(g); i++) {
        if (!r) r = crypto_hash_sha512_update(&hash, &pad, 1);
    }
    if (!r) r = crypto_hash_sha512_update(&hash, g, sizeof(g));
    if (!r) r = crypto_hash_sha512_final(&hash, srp->k);

    /* update client proof */

    /* digest1 = H(N) */
            r = crypto_hash_sha512_init(&hash);
    if (!r) r = crypto_hash_sha512_update(&hash, N, sizeof(N));
    if (!r) r = crypto_hash_sha512_final(&hash, digest1);

    /* digest2 = H(g) */
            r = crypto_hash_sha512_init(&hash);
    if (!r) r = crypto_hash_sha512_update(&hash, g, sizeof(g));
    if (!r) r = crypto_hash_sha512_final(&hash, digest2);

    /* digest1 = H(N) ^ H(g) */
    if (r == 0) {
        for (i = 0, j = crypto_hash_sha512_BYTES; i < j; i++)
            digest1[i] ^= digest2[i];
    }

    /* digest2 = H(user) */
            r = crypto_hash_sha512_init(&hash);
    if (!r) r = crypto_hash_sha512_update(&hash, username, strlen(username));
    if (!r) r = crypto_hash_sha512_final(&hash, digest2);

    /* client proof = H( H(N) ^ H(g) | H(user) | salt) */
    if (!r) r = crypto_hash_sha512_update(&srp->client_proof, digest1, j);
    if (!r) r = crypto_hash_sha512_update(&srp->client_proof, digest2, j);
    if (!r) r = crypto_hash_sha512_update(&srp->client_proof, salt, sizeof(salt));

    DEBUG("Setting SRP password");

    /* digest = H(username | ':' | password) */
            r = crypto_hash_sha512_init(&hash);
    if (!r) r = crypto_hash_sha512_update(&hash, username, strlen(username));
    if (!r) r = crypto_hash_sha512_update(&hash, ":", 1);
    if (!r) r = crypto_hash_sha512_update(&hash, password, strlen(password));
    if (!r) r = crypto_hash_sha512_final(&hash, digest1);

    /* digest = H(salt | H(username | ':' | password)) */
            r = crypto_hash_sha512_init(&hash);
    if (!r) r = crypto_hash_sha512_update(&hash, srp->salt, srp->saltSz);
    if (!r) r = crypto_hash_sha512_update(&hash, digest1, crypto_hash_sha512_BYTES);
    if (!r) r = crypto_hash_sha512_final(&hash, digest1);

    /* Set x (private key) */
    if (!r) r = bignum_set_unsigned_bin(srp->auth, digest1, crypto_hash_sha512_BYTES);

    DEBUG("Getting SRP verifier");
    size_t verifierLen = 1024;
    uint8_t verifier[verifierLen];

    /* v = g ^ x % N */
    struct bignum *v = bignum_init();
    if (v) {
        if (!r) r = bignum_exptmod(srp->g, srp->auth, srp->N, v);
//      if (!r) r = verifierLen < bignum_get_unsigned_bin_len(v) ? ENOMEM : 0;
        if (!r) r = bignum_get_unsigned_bin(v, verifier, &verifierLen);
        bignum_deinit(v);
    }
    if (r) {
        DEBUG("Failed to get SRP verifier (code %d)", r);
        return r;
    }

    DEBUG("Setting SRP verifier");
    r = bignum_set_unsigned_bin(srp->auth, verifier, verifierLen);
    if (r) {
        DEBUG("Failed to set SRP verifier (code %d)", r);
        return r;
    }
#endif
    return 0;
}


int crypto_srp_get_salt(Srp *srp, byte *buffer, size_t *buffer_size) {
    if (buffer_size == NULL)
        return -1;

    if (*buffer_size < srp->saltSz) {
        *buffer_size = srp->saltSz;
        return -2;
    }

    memcpy(buffer, srp->salt, srp->saltSz);
    *buffer_size = srp->saltSz;
    return 0;
}


int crypto_srp_get_public_key(Srp *srp, byte *buffer, size_t *buffer_size) {
    if (buffer_size == NULL)
        return -1;

    // TODO: Fix hardcoded public key size
    if (*buffer_size < 384) {
        *buffer_size = 384;
        return -2;
    }

    DEBUG("Calculating public key");
#ifdef USE_WOLFSSL
    word32 len = *buffer_size;
    int r = wc_SrpGetPublic(srp, buffer, &len);
    *buffer_size = len;
#else
    struct bignum *pubkey = bignum_init();
    int r = 0;

    /* priv = random() */
    if (bignum_get_unsigned_bin_len(srp->priv) == 0) {
        struct bignum *p = bignum_init();
        homekit_random_fill(buffer, SRP_PRIVATE_KEY_MIN_BITS / 8);
        if (!r) r = bignum_set_unsigned_bin(p, buffer, SRP_PRIVATE_KEY_MIN_BITS / 8);
        if (!r) r = bignum_mod(p, srp->N, srp->priv);
//      if (!r) r = bignum_get_unsigned_bin_len(srp->priv) == 0 ? SRP_BAD_KEY_E : 0;
        bignum_deinit(p);
    }

    /* server side: B = (k * v + (g ^ b % N)) % N */
    struct bignum *i = bignum_init();
    struct bignum *j = bignum_init();
    if (!r) r = bignum_set_unsigned_bin(i, srp->k, crypto_hash_sha512_BYTES);
//  if (!r) r = bignum_get_unsigned_bin_len(i) == 0 ? SRP_BAD_KEY_E : 0;
    if (!r) r = bignum_exptmod(srp->g, srp->priv, srp->N, pubkey);
    if (!r) r = bignum_mulmod(i, srp->auth, srp->N, j);
    if (!r) r = bignum_add(j, pubkey, i);
    if (!r) r = bignum_mod(i, srp->N, pubkey);
    bignum_deinit(i);
    bignum_deinit(j);

    /* extract public key to buffer */
    memset(buffer, 0, 384);
    if (!r) r = bignum_get_unsigned_bin(pubkey, buffer, buffer_size);
    bignum_deinit(pubkey);
#endif
    return r;
}


int crypto_srp_compute_key(
    Srp *srp,
    const byte *client_public_key, size_t client_public_key_size,
    const byte *server_public_key, size_t server_public_key_size
) {
#ifdef USE_WOLFSSL
    int r = wc_SrpComputeKey(
        srp,
        (byte *)client_public_key, client_public_key_size,
        (byte *)server_public_key, server_public_key_size
    );
#else
    /* initializing variables */

    size_t secretSz = bignum_get_unsigned_bin_len(srp->N);
    byte *secret = malloc(secretSz);
    struct bignum *u = bignum_init();
    struct bignum *s = bignum_init();
    struct bignum *temp1 = bignum_init();
    struct bignum *temp2 = bignum_init();
    if (secret == NULL || u == NULL || s == NULL || temp1 == NULL || temp2 == NULL) {
        free(secret);
        bignum_deinit(u);
        bignum_deinit(s);
        bignum_deinit(temp1);
        bignum_deinit(temp2);
        return ENOMEM;
    }

    /* building u (random scrambling parameter) */

    struct crypto_hash_sha512_state hash;
    crypto_hash_sha512_init(&hash);

    int i = 0;
    int r = 0;
    byte pad = 0;

    /* H(A) */
    for (i = 0; !r && i < secretSz - client_public_key_size; i++)
        r = crypto_hash_sha512_update(&hash, &pad, 1);
    if (!r) r = crypto_hash_sha512_update(&hash, client_public_key, client_public_key_size);

    /* H(A | B) */
    for (i = 0; !r && i < secretSz - server_public_key_size; i++)
        r = crypto_hash_sha512_update(&hash, &pad, 1);
    if (!r) r = crypto_hash_sha512_update(&hash, server_public_key, server_public_key_size);

    /* set u */
    byte digest[crypto_hash_sha512_BYTES];
    if (!r) r = crypto_hash_sha512_final(&hash, digest);
    if (!r) r = bignum_set_unsigned_bin(u, digest, crypto_hash_sha512_BYTES);

    /* building s (secret) */

    /* temp1 = v ^ u % N */
    r = bignum_exptmod(srp->auth, u, srp->N, temp1);

    /* temp2 = A * temp1 % N; rejects A == 0, A >= N */
    if (!r) r = bignum_set_unsigned_bin(s, client_public_key, client_public_key_size);
//  if (!r) r = bignum_get_unsigned_bin_len(s) == 0 ? EINVAL : 0;
//  if (!r) r = bignum_cmp(s, srp->N) != -1 ? EINVAL : 0;
    if (!r) r = bignum_mulmod(s, temp1, srp->N, temp2);

    /* rejects A * v ^ u % N >= 1, A * v ^ u % N == -1 % N */
    if (!r) r = bignum_set_unsigned_bin(temp1, "\001", 1);
//  if (!r) r = bignum_cmp(temp2, temp1) != 1 ? EINVAL : 0;
    if (!r) r = bignum_sub(srp->N, temp1, s);
//  if (!r) r = bignum_cmp(temp2, s) == 0 ? EINVAL : 0;

    /* secret = temp2 * b % N */
    if (!r) r = bignum_exptmod(temp2, srp->priv, srp->N, s);

    /* building session key from secret */

    if (!r) r = bignum_get_unsigned_bin(s, secret, &secretSz);
    if (!r) r = crypto_srp_key(srp, secret, bignum_get_unsigned_bin_len(s));

    /* updating client proof = H( H(N) ^ H(g) | H(user) | salt | A | B | K) */

    if (!r) r = crypto_hash_sha512_update(&srp->client_proof, client_public_key, client_public_key_size);
    if (!r) r = crypto_hash_sha512_update(&srp->client_proof, server_public_key, server_public_key_size);
    if (!r) r = crypto_hash_sha512_update(&srp->client_proof, srp->key, srp->keySz);

    /* updating server proof = H(A) */

    if (!r) r = crypto_hash_sha512_update(&srp->server_proof, client_public_key, client_public_key_size);

    free(secret);
    bignum_deinit(u);
    bignum_deinit(s);
    bignum_deinit(temp1);
    bignum_deinit(temp2);
#endif
    if (r) {
        DEBUG("Failed to generate SRP shared secret key (code %d)", r);
        return r;
    }

    return 0;
}


int crypto_srp_verify(Srp *srp, const byte *proof, size_t proof_size) {
#ifdef USE_WOLFSSL
    int r = wc_SrpVerifyPeersProof(srp, (byte *)proof, proof_size);
#else
    byte digest[crypto_hash_sha512_BYTES];
    int r = crypto_hash_sha512_final(&srp->client_proof, digest);

    /* server proof = H( A | client proof | K) */
    if (!r) r = crypto_hash_sha512_update(&srp->server_proof, proof, proof_size);
    if (!r) r = crypto_hash_sha512_update(&srp->server_proof, srp->key, srp->keySz);
    if (!r && memcmp(proof, digest, proof_size) != 0)
        r = EINVAL;
#endif
    if (r) {
        DEBUG("Failed to verify client SRP proof (code %d)", r);
        return r;
    }
    return r;
}


int crypto_srp_get_proof(Srp *srp, byte *proof, size_t *proof_size) {
    if (proof_size == NULL)
        return -1;
#ifdef USE_WOLFSSL
    if (*proof_size < WC_SHA512_DIGEST_SIZE) {
        *proof_size = WC_SHA512_DIGEST_SIZE;
        return -2;
    }

    word32 proof_len = *proof_size;
    int r = wc_SrpGetProof(srp, proof, &proof_len);
#else
    if (*proof_size < crypto_hash_sha512_BYTES) {
        *proof_size = crypto_hash_sha512_BYTES;
        return -2;
    }

    size_t proof_len = *proof_size;
    int r = crypto_hash_sha512_final(&srp->server_proof, proof);
#endif
    *proof_size = proof_len;
    return r;
}


int crypto_hkdf(
    const byte *key, size_t key_size,
    const byte *salt, size_t salt_size,
    const byte *info, size_t info_size,
    byte *output, size_t *output_size
) {
    if (output_size == NULL)
        return -1;

    if (*output_size < 32) {
        *output_size = 32;
        return -2;
    }

    *output_size = 32;
#ifdef USE_WOLFSSL
    int r = wc_HKDF(
        SHA512,
        key, key_size,
        salt, salt_size,
        info, info_size,
        output, *output_size
    );
#else
    byte prk[crypto_kdf_hkdf_sha512_KEYBYTES];
    int r = crypto_kdf_hkdf_sha512_extract(prk, salt, salt_size, key, key_size);
    if (!r) r = crypto_kdf_hkdf_sha512_expand(output, 32, info, info_size, prk);
#endif

    return r;
}


int crypto_srp_hkdf(
    Srp *srp,
    const byte *salt, size_t salt_size,
    const byte *info, size_t info_size,
    byte *output, size_t *output_size
) {
    return crypto_hkdf(
        srp->key, srp->keySz,
        salt, salt_size,
        info, info_size,
        output, output_size
    );
}


int crypto_chacha20poly1305_decrypt(
    const byte *key, const byte *nonce, const byte *aad, size_t aad_size,
    const byte *message, size_t message_size,
    byte *decrypted, size_t *decrypted_size
) {
    if (message_size <= CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
        DEBUG("Decrypted message is too small");
        return -2;
    }

    if (decrypted_size == NULL)
        return -1;

    size_t len = message_size - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    if (*decrypted_size < len) {
        *decrypted_size = len;
        return -2;
    }
    delay(0);

    *decrypted_size = len;
#ifdef USE_WOLFSSL
    int r = wc_ChaCha20Poly1305_Decrypt(
        key, nonce, aad, aad_size,
        message, len,
        message+len, decrypted
    );
#else
    int r = crypto_aead_chacha20poly1305_ietf_decrypt(
        decrypted, NULL, NULL,
        message, message_size,
        aad, aad_size,
        nonce, key);
#endif
    delay(0);
    return r;
}

int crypto_chacha20poly1305_encrypt(
    const byte *key, const byte *nonce, const byte *aad, size_t aad_size,
    const byte *message, size_t message_size,
    byte *encrypted, size_t *encrypted_size
) {
    if (encrypted_size == NULL)
        return -1;

    size_t len = message_size + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    if (*encrypted_size < len) {
        *encrypted_size = len;
        return -1;
    }
    delay(0);

    *encrypted_size = len;
#ifdef USE_WOLFSSL
    int r = wc_ChaCha20Poly1305_Encrypt(
        key, nonce, aad, aad_size,
        message, message_size,
        encrypted, encrypted+message_size
    );
#else
    int r = crypto_aead_chacha20poly1305_ietf_encrypt(
        encrypted, NULL,
        message, message_size,
        aad, aad_size,
        NULL, nonce, key);
#endif
    delay(0);
    return r;
}


int crypto_ed25519_init(ed25519_key *key) {
#ifdef USE_WOLFSSL
    int r = wc_ed25519_init(key);
    if (r) {
        return r;
    }
#else
    memset(key->p, 0, sizeof(key->p));
    memset(key->k, 0, sizeof(key->k));
#endif
    return 0;
}


ed25519_key *crypto_ed25519_new() {
    ed25519_key *key = malloc(sizeof(ed25519_key));
    int r = crypto_ed25519_init(key);
    if (r) {
        free(key);
        return NULL;
    }
    return key;
}


void crypto_ed25519_free(ed25519_key *key) {
    if (key)
        free(key);
}

int crypto_ed25519_generate(ed25519_key *key) {
    int r;
    r = crypto_ed25519_init(key);
    if (r)
        return r;
    delay(0);
#ifdef USE_WOLFSSL
    WC_RNG rng;
    r = wc_InitRng(&rng);
    if (r) {
        DEBUG("Failed to initialize RNG (code %d)", r);
        return r;
    }

    r = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, key);
#else
    r = crypto_sign_ed25519_keypair(key->p, key->k);
#endif
    if (r) {
        DEBUG("Failed to generate key (code %d)", r);
        return r;
    }
    delay(0);
    return 0;
}

int crypto_ed25519_import_key(ed25519_key *key, const byte *data, size_t size) {
#ifdef USE_WOLFSSL
    return wc_ed25519_import_private_key(
        data, ED25519_KEY_SIZE,
        data + ED25519_KEY_SIZE, ED25519_PUB_KEY_SIZE,
        key
    );
#else
    memcpy(key->p, data + ED25519_KEYSIZE, ED25519_PUBLIC_KEYSIZE);
    memcpy(key->k, data, ED25519_KEYSIZE);
    memcpy(key->p + ED25519_KEYSIZE, key->p, ED25519_PUBLIC_KEYSIZE);
    return 0;
#endif
}

int crypto_ed25519_export_key(const ed25519_key *key, byte *buffer, size_t *size) {
    if (size == NULL)
        return -1;
#ifdef USE_WOLFSSL
    if (*size < ED25519_KEY_SIZE + ED25519_PUB_KEY_SIZE) {
        *size = ED25519_KEY_SIZE + ED25519_PUB_KEY_SIZE;
        return -2;
    }

    word32 key_size = *size;
    int r = wc_ed25519_export_private((ed25519_key *)key, buffer, &key_size);
#else
    if (*size < ED25519_SECRET_KEYSIZE) {
        *size = ED25519_SECRET_KEYSIZE;
        return -2;
    }

    size_t key_size = *size;
    int r = memcpy(buffer, key->k, key_size) != buffer;
#endif
    *size = key_size;
    return r;
}

int crypto_ed25519_import_public_key(ed25519_key *key, const byte *data, size_t size) {
#ifdef USE_WOLFSSL
    return wc_ed25519_import_public(data, size, key);
#else
    return memcpy(key->p, data, size) != key->p;
#endif
}

int crypto_ed25519_export_public_key(const ed25519_key *key, byte *buffer, size_t *size) {
    if (size == NULL) {
        return -1;
    }
#ifdef USE_WOLFSSL
    if (*size < ED25519_PUB_KEY_SIZE) {
        *size = ED25519_PUB_KEY_SIZE;
        return -2;
    }

    word32 len = *size;
    int r = wc_ed25519_export_public((ed25519_key *)key, buffer, &len);
#else
    if (*size < ED25519_PUBLIC_KEYSIZE) {
        *size = ED25519_PUBLIC_KEYSIZE;
        return -2;
    }

    size_t len = *size;
    int r = memcpy(buffer, key->p, len) != buffer;
#endif
    *size = len;
    return r;
}


int crypto_ed25519_sign(
    const ed25519_key *key,
    const byte *message, size_t message_size,
    byte *signature, size_t *signature_size
) {
    if (signature_size == NULL) {
        return -1;
    }
    delay(0);
#ifdef USE_WOLFSSL
    if (*signature_size < ED25519_SIG_SIZE) {
        *signature_size = ED25519_SIG_SIZE;
        return -2;
    }

    word32 len = *signature_size;
    int r = wc_ed25519_sign_msg(
        message, message_size,
        signature, &len,
        (ed25519_key *)key
    );
    *signature_size = len;
#else
    if (*signature_size < ED25519_SIGN_KEYSIZE + message_size) {
        *signature_size = ED25519_SIGN_KEYSIZE + message_size;
        return -2;
    }

    unsigned long long len = *signature_size;
    int r = crypto_sign_ed25519(signature, &len, message, message_size, key->k);
    *signature_size = ED25519_SIGN_KEYSIZE;
#endif
    delay(0);
    return r;
}


int crypto_ed25519_verify(
    const ed25519_key *key,
    const byte *message, size_t message_size,
    const byte *signature, size_t signature_size
) {
    int verified;
    delay(0);
#ifdef USE_WOLFSSL
    int r = wc_ed25519_verify_msg(
        signature, signature_size,
        message, message_size,
        &verified, (ed25519_key *)key
    );
#else
    byte sm[signature_size + message_size];
    byte m[signature_size + message_size];
    memcpy(sm, signature, signature_size);
    memcpy(sm + signature_size, message, message_size);
    unsigned long long mlen;
    int r = crypto_sign_ed25519_open(m, &mlen, sm, signature_size + message_size, key->p);
    verified = r ? 0 : 1;
#endif
    delay(0);
    return !r && !verified;
}


int crypto_curve25519_init(curve25519_key *key) {
#ifdef USE_WOLFSSL
    int r = wc_curve25519_init(key);
    if (r) {
        return r;
    }
#else
    memset(key->p, 0, sizeof(key->p));
    memset(key->k, 0, sizeof(key->k));
#endif
    return 0;
}


void crypto_curve25519_done(curve25519_key *key) {
#ifdef USE_WOLFSSL
    if (!key)
        return;

    wc_curve25519_free(key);
#else
    memset(key->p, 0, sizeof(key->p));
    memset(key->k, 0, sizeof(key->k));
#endif
}


int crypto_curve25519_generate(curve25519_key *key) {
    int r;
    r = crypto_curve25519_init(key);
    if (r) {
        return r;
    }
    delay(0);
#ifdef USE_WOLFSSL
    WC_RNG rng;
    r = wc_InitRng(&rng);
    if (r) {
        DEBUG("Failed to initialize RNG (code %d)", r);
        return r;
    }

    r = wc_curve25519_make_key(&rng, 32, key);
#else
    homekit_random_fill(key->k, CURVE25519_KEYSIZE);

    /* Clamp the private key */
    key->k[0] &= 248;
    key->k[CURVE25519_KEYSIZE - 1] &= 63; /* same &=127 because |=64 after */
    key->k[CURVE25519_KEYSIZE - 1] |= 64;

    /* compute public key */
    r = crypto_scalarmult_curve25519_base(key->p, key->k);
#endif
    if (r) {
        crypto_curve25519_done(key);
        return r;
    }
    delay(0);
    return 0;
}


int crypto_curve25519_import_public(curve25519_key *key, const byte *data, size_t size) {
#ifdef USE_WOLFSSL
    return wc_curve25519_import_public_ex(data, size, key, EC25519_LITTLE_ENDIAN);
#else
    return memcpy(key->p, data, size) != key->p;
#endif
}


int crypto_curve25519_export_public(const curve25519_key *key, byte *buffer, size_t *size) {
#ifdef USE_WOLFSSL
    if (*size == 0) {
        word32 len = 0;
        int r = wc_curve25519_export_public_ex(
            (curve25519_key *)key,
            (byte *)&len, &len,
            EC25519_LITTLE_ENDIAN
        );
        *size = len;
        return r;
    }

    word32 len = *size;
    int r = wc_curve25519_export_public_ex(
        (curve25519_key *)key,
        buffer, &len,
        EC25519_LITTLE_ENDIAN
    );
#else
    if (*size < CURVE25519_KEYSIZE) {
        *size = CURVE25519_KEYSIZE;
        return -2;
    }

    size_t len = *size;
    int r = memcpy(buffer, key->p, len) != buffer;
#endif
    *size = len;
    return r;
}


int crypto_curve25519_shared_secret(const curve25519_key *private_key, const curve25519_key *public_key, byte *buffer, size_t *size) {
    if (*size < CURVE25519_KEYSIZE) {
        *size = CURVE25519_KEYSIZE;
        return -2;
    }
    delay(0);
#ifdef USE_WOLFSSL
    word32 len = *size;
    int r = wc_curve25519_shared_secret_ex(
        (curve25519_key *)private_key,
        (curve25519_key *)public_key,
        buffer, &len, EC25519_LITTLE_ENDIAN
    );
#else
    size_t len = *size;
    int r = crypto_scalarmult_curve25519(buffer, private_key->k, public_key->p);
#endif
    *size = len;
    delay(0);
    return r;
}

