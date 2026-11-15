#define TEST_NAME "kx2"
#include "cmptest.h"

#define NB_CLIENTS 3
#define NB_SERVERS 3
#define SENTINEL 0x42

/*
 * Low-order and non-canonical X25519 public keys.
 * A peer must never be able to use any of these to make a key
 * agreement succeed, and a failed agreement must not leave behind
 * output that could be mistaken for valid key material.
 */
static const unsigned char bad_pks[][crypto_kx_PUBLICKEYBYTES] = {
    /* 0 (order 4) */
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 1 (order 1) */
    { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    /* 325606250916557431795983626356110631294008115727848805560023387167927233504
       (order 8) */
    { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
      0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
      0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
    /* 39382357235489614581723060781553021112529911719440698176882885853963445705823
       (order 8) */
    { 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
      0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
      0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
    /* p-1 (order 2) */
    { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    /* p (=0, order 4) */
    { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
    /* p+1 (=1, order 1) */
    { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
};

static void
make_seed(unsigned char seed[crypto_kx_SEEDBYTES], unsigned char tag, int idx)
{
    size_t i;

    for (i = 0; i < crypto_kx_SEEDBYTES; i++) {
        seed[i] = (unsigned char) (tag + (unsigned char) (idx * 17) +
                                   (unsigned char) (i * 3));
    }
}

static int
holds_sentinel(const unsigned char *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (buf[i] != SENTINEL) {
            return 0;
        }
    }
    return 1;
}

static void
print_key(const char *label, const unsigned char *key)
{
    char hex[2 * crypto_kx_SESSIONKEYBYTES + 1];

    sodium_bin2hex(hex, sizeof hex, key, crypto_kx_SESSIONKEYBYTES);
    printf("%s: [%s]\n", label, hex);
}

/*
 * Finite matrix of client/server key pairs: for every correct pairing,
 * the two directions of the bidirectional channel must be complementary
 * (client tx == server rx, client rx == server tx), and distinct
 * pairings must yield distinct keys.
 */
static void
tv_kx_pairing_matrix(void)
{
    unsigned char seed[crypto_kx_SEEDBYTES];
    unsigned char client_pk[NB_CLIENTS][crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[NB_CLIENTS][crypto_kx_SECRETKEYBYTES];
    unsigned char server_pk[NB_SERVERS][crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[NB_SERVERS][crypto_kx_SECRETKEYBYTES];
    unsigned char c_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char c_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char s_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char s_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char ref_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char ref_tx[crypto_kx_SESSIONKEYBYTES];
    int           i;
    int           j;

    for (i = 0; i < NB_CLIENTS; i++) {
        make_seed(seed, 0x10, i);
        crypto_kx_seed_keypair(client_pk[i], client_sk[i], seed);
    }
    for (j = 0; j < NB_SERVERS; j++) {
        make_seed(seed, 0x80, j);
        crypto_kx_seed_keypair(server_pk[j], server_sk[j], seed);
    }
    memset(ref_rx, 0, sizeof ref_rx);
    memset(ref_tx, 0, sizeof ref_tx);

    for (i = 0; i < NB_CLIENTS; i++) {
        for (j = 0; j < NB_SERVERS; j++) {
            assert(crypto_kx_client_session_keys(c_rx, c_tx,
                                                 client_pk[i], client_sk[i],
                                                 server_pk[j]) == 0);
            assert(crypto_kx_server_session_keys(s_rx, s_tx,
                                                 server_pk[j], server_sk[j],
                                                 client_pk[i]) == 0);
            /* bidirectional complementarity */
            assert(memcmp(c_tx, s_rx, crypto_kx_SESSIONKEYBYTES) == 0);
            assert(memcmp(c_rx, s_tx, crypto_kx_SESSIONKEYBYTES) == 0);
            /* send and receive directions are bound to different keys */
            assert(memcmp(c_rx, c_tx, crypto_kx_SESSIONKEYBYTES) != 0);
            assert(memcmp(s_rx, s_tx, crypto_kx_SESSIONKEYBYTES) != 0);
            if (i == 0 && j == 0) {
                memcpy(ref_rx, c_rx, sizeof ref_rx);
                memcpy(ref_tx, c_tx, sizeof ref_tx);
                print_key("client_rx", c_rx);
                print_key("client_tx", c_tx);
            } else {
                /* a different pairing must not reuse the same keys */
                assert(memcmp(c_rx, ref_rx, crypto_kx_SESSIONKEYBYTES) != 0);
                assert(memcmp(c_tx, ref_tx, crypto_kx_SESSIONKEYBYTES) != 0);
            }
            printf("pair %d/%d: ok\n", i, j);
        }
    }
}

/*
 * A party using the wrong role must not end up with a channel that
 * interoperates with the peer's.
 */
static void
tv_kx_role_swap(void)
{
    unsigned char seed[crypto_kx_SEEDBYTES];
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char c_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char c_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char s_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char s_tx[crypto_kx_SESSIONKEYBYTES];

    make_seed(seed, 0x10, 0);
    crypto_kx_seed_keypair(client_pk, client_sk, seed);
    make_seed(seed, 0x80, 0);
    crypto_kx_seed_keypair(server_pk, server_sk, seed);

    /* both parties assume the client role */
    assert(crypto_kx_client_session_keys(c_rx, c_tx,
                                         client_pk, client_sk,
                                         server_pk) == 0);
    assert(crypto_kx_client_session_keys(s_rx, s_tx,
                                         server_pk, server_sk,
                                         client_pk) == 0);
    assert(memcmp(c_tx, s_rx, crypto_kx_SESSIONKEYBYTES) != 0);
    assert(memcmp(c_rx, s_tx, crypto_kx_SESSIONKEYBYTES) != 0);
    printf("both-as-client: no common channel\n");

    /* both parties assume the server role */
    assert(crypto_kx_server_session_keys(s_rx, s_tx,
                                         server_pk, server_sk,
                                         client_pk) == 0);
    assert(crypto_kx_server_session_keys(c_rx, c_tx,
                                         client_pk, client_sk,
                                         server_pk) == 0);
    assert(memcmp(c_tx, s_rx, crypto_kx_SESSIONKEYBYTES) != 0);
    assert(memcmp(c_rx, s_tx, crypto_kx_SESSIONKEYBYTES) != 0);
    printf("both-as-server: no common channel\n");
}

/*
 * Keying to the wrong peer public key must not produce keys that
 * interoperate with the intended peer, even though the call itself
 * succeeds (the public key is a valid curve point).
 */
static void
tv_kx_wrong_peer(void)
{
    unsigned char seed[crypto_kx_SEEDBYTES];
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char eve_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char eve_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char c_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char c_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char s_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char s_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char e_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char e_tx[crypto_kx_SESSIONKEYBYTES];

    make_seed(seed, 0x10, 0);
    crypto_kx_seed_keypair(client_pk, client_sk, seed);
    make_seed(seed, 0x80, 0);
    crypto_kx_seed_keypair(server_pk, server_sk, seed);
    crypto_kx_keypair(eve_pk, eve_sk);

    /* legitimate channel, for reference */
    assert(crypto_kx_client_session_keys(c_rx, c_tx,
                                         client_pk, client_sk,
                                         server_pk) == 0);
    assert(crypto_kx_server_session_keys(s_rx, s_tx,
                                         server_pk, server_sk,
                                         client_pk) == 0);

    /* server talks to Eve's key instead of the client's */
    assert(crypto_kx_server_session_keys(e_rx, e_tx,
                                         server_pk, server_sk,
                                         eve_pk) == 0);
    assert(memcmp(e_rx, c_tx, crypto_kx_SESSIONKEYBYTES) != 0);
    assert(memcmp(e_tx, c_rx, crypto_kx_SESSIONKEYBYTES) != 0);
    assert(memcmp(e_rx, s_rx, crypto_kx_SESSIONKEYBYTES) != 0);
    assert(memcmp(e_tx, s_tx, crypto_kx_SESSIONKEYBYTES) != 0);

    /* client talks to Eve's key instead of the server's */
    assert(crypto_kx_client_session_keys(e_rx, e_tx,
                                         client_pk, client_sk,
                                         eve_pk) == 0);
    assert(memcmp(e_rx, s_tx, crypto_kx_SESSIONKEYBYTES) != 0);
    assert(memcmp(e_tx, s_rx, crypto_kx_SESSIONKEYBYTES) != 0);
    assert(memcmp(e_rx, c_rx, crypto_kx_SESSIONKEYBYTES) != 0);
    assert(memcmp(e_tx, c_tx, crypto_kx_SESSIONKEYBYTES) != 0);

    printf("wrong peer: no common channel\n");
}

/*
 * Low-order and malformed peer public keys must be rejected: the return
 * value must signal failure and the output buffers must not be filled
 * with anything a caller could mistake for negotiated key material.
 */
static void
tv_kx_bad_public_keys(void)
{
    unsigned char seed[crypto_kx_SEEDBYTES];
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];
    size_t        i;

    make_seed(seed, 0x10, 0);
    crypto_kx_seed_keypair(client_pk, client_sk, seed);
    make_seed(seed, 0x80, 0);
    crypto_kx_seed_keypair(server_pk, server_sk, seed);

    for (i = 0; i < sizeof bad_pks / sizeof bad_pks[0]; i++) {
        memset(rx, SENTINEL, sizeof rx);
        memset(tx, SENTINEL, sizeof tx);
        assert(crypto_kx_client_session_keys(rx, tx,
                                             client_pk, client_sk,
                                             bad_pks[i]) == -1);
        assert(holds_sentinel(rx, sizeof rx));
        assert(holds_sentinel(tx, sizeof tx));

        memset(rx, SENTINEL, sizeof rx);
        memset(tx, SENTINEL, sizeof tx);
        assert(crypto_kx_server_session_keys(rx, tx,
                                             server_pk, server_sk,
                                             bad_pks[i]) == -1);
        assert(holds_sentinel(rx, sizeof rx));
        assert(holds_sentinel(tx, sizeof tx));

        printf("bad_pk %u: rejected\n", (unsigned int) i);
    }
}

int
main(void)
{
    tv_kx_pairing_matrix();
    tv_kx_role_swap();
    tv_kx_wrong_peer();
    tv_kx_bad_public_keys();

    printf("tv_kx2: ok\n");

    return 0;
}
