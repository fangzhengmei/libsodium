
#define TEST_NAME "box_seal2"
#include "cmptest.h"

#define MLEN 42U
#define MAX_MLEN 1000U
#define CANARY 0xa5

/*
 * Recompute the nonce the way crypto_box_seal()/crypto_box_seal_open()
 * derive it internally: blake2b(ephemeral_pk || recipient_pk).
 * Used to drive the low-level crypto_box_open_easy() interface directly,
 * so tests can tell apart rejections happening in the outer seal wrapper
 * (ciphertext length guard) from rejections in the underlying public-key
 * authenticated decryption layer (MAC verification).
 */
static void
seal_nonce(unsigned char *nonce, const unsigned char *epk,
           const unsigned char *pk)
{
    crypto_generichash_state st;

    crypto_generichash_init(&st, NULL, 0U, crypto_box_NONCEBYTES);
    crypto_generichash_update(&st, epk, crypto_box_PUBLICKEYBYTES);
    crypto_generichash_update(&st, pk, crypto_box_PUBLICKEYBYTES);
    crypto_generichash_final(&st, nonce, crypto_box_NONCEBYTES);
}

/* Success paths: empty message and messages of assorted lengths. */
static void
tv_roundtrip(void)
{
    static const size_t lens[] = { 0U, 1U, 7U, 32U, 255U, MAX_MLEN };
    unsigned char  pk[crypto_box_PUBLICKEYBYTES];
    unsigned char  sk[crypto_box_SECRETKEYBYTES];
    unsigned char *c;
    unsigned char *m;
    unsigned char *m2;
    size_t         m_len;
    size_t         i;

    crypto_box_keypair(pk, sk);
    m  = (unsigned char *) sodium_malloc(MAX_MLEN);
    m2 = (unsigned char *) sodium_malloc(MAX_MLEN);
    c  = (unsigned char *) sodium_malloc(crypto_box_SEALBYTES + MAX_MLEN);
    for (i = 0U; i < sizeof lens / sizeof lens[0]; i++) {
        m_len = lens[i];
        randombytes_buf(m, m_len);
        if (crypto_box_seal(c, m, m_len, pk) != 0) {
            printf("crypto_box_seal() failure\n");
            break;
        }
        printf("%d\n", crypto_box_seal_open(m2, c,
                                            crypto_box_SEALBYTES + m_len,
                                            pk, sk));
        printf("%d\n", memcmp(m, m2, m_len));
    }
    sodium_free(c);
    sodium_free(m);
    sodium_free(m2);
}

/*
 * Authentication failure matrix: corrupted ephemeral public key, truncated
 * ciphertext and substituted recipient, crossed with each other.
 * Every case must return -1 and must leave the caller's output buffer
 * untouched, so no failure can produce plaintext a caller could trust.
 */
static void
tv_failure_matrix(void)
{
    unsigned char  pk[crypto_box_PUBLICKEYBYTES];
    unsigned char  sk[crypto_box_SECRETKEYBYTES];
    unsigned char  pk2[crypto_box_PUBLICKEYBYTES];
    unsigned char  sk2[crypto_box_SECRETKEYBYTES];
    unsigned char  nonce[crypto_box_NONCEBYTES];
    unsigned char *c;
    unsigned char *c_orig;
    unsigned char *canary;
    unsigned char *m;
    unsigned char *m2;
    size_t         c_len = crypto_box_SEALBYTES + MLEN;
    size_t         body_len = c_len - crypto_box_PUBLICKEYBYTES;

    crypto_box_keypair(pk, sk);
    crypto_box_keypair(pk2, sk2);
    m      = (unsigned char *) sodium_malloc(MLEN);
    m2     = (unsigned char *) sodium_malloc(MLEN);
    canary = (unsigned char *) sodium_malloc(MLEN);
    c      = (unsigned char *) sodium_malloc(c_len);
    c_orig = (unsigned char *) sodium_malloc(c_len);
    randombytes_buf(m, MLEN);
    memset(canary, CANARY, MLEN);
    if (crypto_box_seal(c, m, MLEN, pk) != 0) {
        printf("crypto_box_seal() failure\n");
        return;
    }
    memcpy(c_orig, c, c_len);

    /* 1. wrong ephemeral public key */
    c[0] ^= 0x01;
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, c_len, pk, sk));
    printf("%d\n", memcmp(m2, canary, MLEN));
    memcpy(c, c_orig, c_len);

    /* 2. short ciphertext */
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, crypto_box_SEALBYTES - 1U,
                                        pk, sk));
    printf("%d\n", memcmp(m2, canary, MLEN));

    /* 3. empty ciphertext */
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, 0U, pk, sk));
    printf("%d\n", memcmp(m2, canary, MLEN));

    /* 4. substituted recipient */
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, c_len, pk2, sk2));
    printf("%d\n", memcmp(m2, canary, MLEN));

    /* 5. wrong ephemeral public key + short ciphertext */
    c[0] ^= 0x01;
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, crypto_box_SEALBYTES - 1U,
                                        pk, sk));
    printf("%d\n", memcmp(m2, canary, MLEN));
    memcpy(c, c_orig, c_len);

    /* 6. wrong ephemeral public key + substituted recipient */
    c[0] ^= 0x01;
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, c_len, pk2, sk2));
    printf("%d\n", memcmp(m2, canary, MLEN));
    memcpy(c, c_orig, c_len);

    /* 7. short ciphertext + substituted recipient */
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, crypto_box_SEALBYTES - 1U,
                                        pk2, sk2));
    printf("%d\n", memcmp(m2, canary, MLEN));

    /* 8. tampered message body (last byte) */
    c[c_len - 1U] ^= 0x01;
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, c_len, pk, sk));
    printf("%d\n", memcmp(m2, canary, MLEN));
    memcpy(c, c_orig, c_len);

    /*
     * Layer attribution: compare the outer crypto_box_seal_open() interface
     * with the underlying crypto_box_open_easy() public-key operation.
     */

    /* Short ciphertext: the outer wrapper rejects a buffer that still holds
     * a fully valid sealed message, while the low-level layer accepts the
     * same body. The rejection therefore comes from the outer length guard,
     * not from the public-key layer. */
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, crypto_box_SEALBYTES - 1U,
                                        pk, sk));
    seal_nonce(nonce, c, pk);
    printf("%d\n", crypto_box_open_easy(m2, c + crypto_box_PUBLICKEYBYTES,
                                        body_len, nonce, c, sk));
    printf("%d\n", memcmp(m, m2, MLEN));

    /* Wrong ephemeral public key: the length guard passes, and the
     * low-level public-key layer rejects with the nonce the outer layer
     * would derive. The rejection happens in the inner layer. */
    c[0] ^= 0x01;
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, c_len, pk, sk));
    seal_nonce(nonce, c, pk);
    printf("%d\n", crypto_box_open_easy(m2, c + crypto_box_PUBLICKEYBYTES,
                                        body_len, nonce, c, sk));
    memcpy(c, c_orig, c_len);

    /* Substituted recipient: rejected by the inner layer when opened with
     * the wrong key pair, while the same body still verifies under the
     * intended recipient's keys. */
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_seal_open(m2, c, c_len, pk2, sk2));
    seal_nonce(nonce, c, pk2);
    printf("%d\n", crypto_box_open_easy(m2, c + crypto_box_PUBLICKEYBYTES,
                                        body_len, nonce, c, sk2));
    seal_nonce(nonce, c, pk);
    printf("%d\n", crypto_box_open_easy(m2, c + crypto_box_PUBLICKEYBYTES,
                                        body_len, nonce, c, sk));

    /*
     * The failed attempts above must not affect subsequent decryptions:
     * the original ciphertext still opens, and newly sealed messages
     * still round-trip.
     */
    printf("%d\n", crypto_box_seal_open(m2, c, c_len, pk, sk));
    printf("%d\n", memcmp(m, m2, MLEN));
    randombytes_buf(m, MLEN);
    if (crypto_box_seal(c, m, MLEN, pk) != 0) {
        printf("crypto_box_seal() failure\n");
        return;
    }
    printf("%d\n", crypto_box_seal_open(m2, c, c_len, pk, sk));
    printf("%d\n", memcmp(m, m2, MLEN));

    sodium_free(c_orig);
    sodium_free(c);
    sodium_free(canary);
    sodium_free(m2);
    sodium_free(m);
}

#ifndef SODIUM_LIBRARY_MINIMAL
static void
tv_xchacha20(void)
{
    unsigned char  pk[crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES];
    unsigned char  sk[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
    unsigned char  pk2[crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES];
    unsigned char  sk2[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
    unsigned char *c;
    unsigned char *c_orig;
    unsigned char *canary;
    unsigned char *m;
    unsigned char *m2;
    size_t         c_len =
        crypto_box_curve25519xchacha20poly1305_SEALBYTES + MLEN;

    crypto_box_curve25519xchacha20poly1305_keypair(pk, sk);
    crypto_box_curve25519xchacha20poly1305_keypair(pk2, sk2);
    m      = (unsigned char *) sodium_malloc(MLEN);
    m2     = (unsigned char *) sodium_malloc(MLEN);
    canary = (unsigned char *) sodium_malloc(MLEN);
    c      = (unsigned char *) sodium_malloc(c_len);
    c_orig = (unsigned char *) sodium_malloc(c_len);
    randombytes_buf(m, MLEN);
    memset(canary, CANARY, MLEN);
    if (crypto_box_curve25519xchacha20poly1305_seal(c, m, MLEN, pk) != 0) {
        printf("crypto_box_curve25519xchacha20poly1305_seal() failure\n");
        return;
    }
    memcpy(c_orig, c, c_len);

    /* round-trip */
    printf("%d\n", crypto_box_curve25519xchacha20poly1305_seal_open(
               m2, c, c_len, pk, sk));
    printf("%d\n", memcmp(m, m2, MLEN));

    /* wrong ephemeral public key */
    c[0] ^= 0x01;
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_curve25519xchacha20poly1305_seal_open(
               m2, c, c_len, pk, sk));
    printf("%d\n", memcmp(m2, canary, MLEN));
    memcpy(c, c_orig, c_len);

    /* short ciphertext */
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_curve25519xchacha20poly1305_seal_open(
               m2, c, crypto_box_curve25519xchacha20poly1305_SEALBYTES - 1U,
               pk, sk));
    printf("%d\n", memcmp(m2, canary, MLEN));

    /* substituted recipient */
    memset(m2, CANARY, MLEN);
    printf("%d\n", crypto_box_curve25519xchacha20poly1305_seal_open(
               m2, c, c_len, pk2, sk2));
    printf("%d\n", memcmp(m2, canary, MLEN));

    /* subsequent normal decryption is unaffected */
    printf("%d\n", crypto_box_curve25519xchacha20poly1305_seal_open(
               m2, c, c_len, pk, sk));
    printf("%d\n", memcmp(m, m2, MLEN));

    sodium_free(c_orig);
    sodium_free(c);
    sodium_free(canary);
    sodium_free(m2);
    sodium_free(m);
}
#else
static void
tv_xchacha20(void)
{
    printf("0\n0\n-1\n0\n-1\n0\n-1\n0\n0\n0\n");
}
#endif

int
main(void)
{
    tv_roundtrip();
    tv_failure_matrix();
    tv_xchacha20();

    return 0;
}
