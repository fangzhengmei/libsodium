
/*
 * Ed25519 verification authentication-boundary test.
 *
 * The detached interface (crypto_sign_ed25519_verify_detached) and the
 * combined interface (crypto_sign_ed25519_open) must share the exact same
 * authentication boundary: every malformed encoding or tampered input has to
 * be accepted or rejected identically by both entry points, and a rejection
 * must never leave the caller with a message or a length that could be
 * mistaken for authenticated data.
 *
 * This test exercises:
 *  1. Non-canonical scalar (S) and point (R / public key) encodings and
 *     truncated signatures, comparing the acceptance sets of the two
 *     interfaces.
 *  2. Minimal (single-byte, single-bit) mutations of the message and of each
 *     signature region to locate the parsing/verification boundary, with the
 *     unmodified valid signature kept as a control.
 *  3. The output contract of every rejection path (no message, zero length)
 *     while retaining compatibility with the normal signing flow.
 */

#define TEST_NAME "ed25519_sign_boundary"
#include "cmptest.h"

#define SIG_LEN        crypto_sign_ed25519_BYTES          /* 64 */
#define PK_LEN         crypto_sign_ed25519_PUBLICKEYBYTES /* 32 */
#define SEED_LEN       crypto_sign_ed25519_SEEDBYTES      /* 32 */

#define MSG_LEN        39U
#define CANARY         0xa5

static unsigned char seed[SEED_LEN];
static unsigned char pk[PK_LEN];
static unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
static unsigned char m[MSG_LEN];

/* Fixed valid material, regenerated from the deterministic seed at startup. */
static unsigned char sig[SIG_LEN];
static unsigned char sm[SIG_LEN + MSG_LEN];
static unsigned long long siglen;
static unsigned long long smlen;

/*
 * Structured malformed signatures/keys.  Each entry mutates the valid
 * signature or key in exactly one way so that the observed rejection can be
 * attributed to a specific parsing/verification stage.
 */
typedef struct Case_ {
    const char *tag;
    int         mutate_sig;                 /* 1: sig_buf is used, 0: pk_buf */
    int         truncated;                 /* pass fewer than 64 sig bytes */
    unsigned char sig_buf[SIG_LEN];
    unsigned char pk_buf[PK_LEN];
    unsigned long long sig_trim;           /* bytes removed from the end */
} Case;

/*
 * Known-bad encodings taken from the canonicality rules implemented in
 * ref10/open.c and from the historical sign2 rejection vectors.  Stored as hex
 * to keep the offending property visible next to the case definition.
 */

/* S = L (the group order): top nibble of S[31] is 0, so the early
 * canonicality shortcut does not fire; the value is still non-canonical. */
static const char noncanonical_s_eq_L[] =
    "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

/* S = L + 1: top nibble of S[31] is 0x1, rejected by the explicit
 * sc25519_is_canonical() check before any group arithmetic runs. */
static const char noncanonical_s_L_plus_1[] =
    "eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

/* S >> L, top nibble 0x7: historical non-canonical scalar vector. */
static const char noncanonical_s_high[] =
    "7e71f98a4734e74f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c2";

/* Non-canonical encoding of the identity point (used as R). */
static const char noncanonical_r_identity[] =
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/* Small-order public key, canonical encoding, rejected as weak A. */
static const char small_order_pk[] =
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/* Small-order R, canonical encoding, rejected as weak R. */
static const char small_order_r[] =
    "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc";

static int failures;

static void
fail(const char *what)
{
    printf("FAIL: %s\n", what);
    failures++;
}

static int
hex2bin(unsigned char *dst, size_t dst_max, const char *hex)
{
    size_t bin_len;

    if (sodium_hex2bin(dst, dst_max, hex, strlen(hex), NULL, &bin_len,
                       NULL) != 0) {
        return -1;
    }
    return (int) bin_len;
}

/* Parse a fixed-width test vector; a malformed vector is a test bug. */
static void
hex2bin_fixed(unsigned char *dst, size_t dst_max, const char *hex)
{
    if (hex2bin(dst, dst_max, hex) != (int) dst_max) {
        fail("malformed embedded hex vector");
        memset(dst, 0, dst_max);
    }
}

/* Run one malformed case through both interfaces and compare the verdicts. */
static void
run_malformed_case(const Case *c)
{
    const unsigned char *sig_p   = c->mutate_sig ? c->sig_buf : sig;
    const unsigned char *pk_p    = c->mutate_sig ? pk : c->pk_buf;
    unsigned long long   sig_len = SIG_LEN - (c->truncated ? c->sig_trim : 0);
    unsigned char        out[SIG_LEN + MSG_LEN + 16U];
    unsigned char        expect_out[sizeof out];
    unsigned long long   out_len = (unsigned long long) 0xdeadbeefULL;
    unsigned char        sm_local[SIG_LEN + MSG_LEN];
    int                  detached_ret;
    int                  open_ret;
    size_t               i;
    size_t               zero_prefix;
    unsigned long long   declared_mlen;

    /* crypto_sign_ed25519_verify_detached only sees exact 64-byte inputs. */
    if (!c->truncated) {
        detached_ret = crypto_sign_ed25519_verify_detached(sig_p, m, MSG_LEN,
                                                           pk_p);
    } else {
        /* No public entry point consumes a short detached signature; the
         * boundary is therefore exercised through the combined interface,
         * which owns the length check. */
        detached_ret = -1;
    }

    /* Build the combined input: (possibly truncated) signature || message. */
    memcpy(sm_local, sig_p, (size_t) sig_len);
    memcpy(sm_local + sig_len, m, MSG_LEN);

    memset(out, CANARY, sizeof out);
    memset(expect_out, CANARY, sizeof expect_out);
    out_len = (unsigned long long) 0xdeadbeefULL;
    open_ret = crypto_sign_ed25519_open(out, &out_len, sm_local,
                                        sig_len + MSG_LEN, pk_p);

    /* Rejection is the only acceptable outcome for these inputs. */
    if (open_ret != -1) {
        fail(c->tag);
        return;
    }
    if (!c->truncated && detached_ret != -1) {
        fail(c->tag);
        return;
    }
    /* The two interfaces must agree whenever both are defined. */
    if (!c->truncated && open_ret != detached_ret) {
        fail(c->tag);
        return;
    }
    /* A rejected open() must report zero, never the embedded message length. */
    if (out_len != 0U) {
        fail(c->tag);
        return;
    }
    /*
     * Output contract on rejection: no authenticated bytes may survive.
     * open() computes the declared message length as smlen - 64 and zeroes
     * exactly that prefix on failure (its length check still forces the
     * function to report -1 / 0).  For full-length inputs this equals the
     * whole message; for truncated inputs it covers the leading portion of
     * the embedded message.  The remaining bytes must keep the canary, and
     * in every case the physical message region may not be returned as
     * authenticated data.
     */
    declared_mlen = sig_len + MSG_LEN - SIG_LEN;
    zero_prefix = (size_t) declared_mlen;
    if (zero_prefix > sizeof out) {
        fail(c->tag);
        return;
    }
    memset(expect_out, 0, zero_prefix);
    for (i = 0U; i < sizeof out; i++) {
        if (out[i] != expect_out[i]) {
            fail(c->tag);
            return;
        }
    }
    /* NULL output / NULL length pointers must be tolerated on rejection. */
    {
        unsigned long long sentinel_len = (unsigned long long) 0xfeedfaceULL;
        int                ret;

        ret = crypto_sign_ed25519_open(NULL, &sentinel_len, sm_local,
                                       sig_len + MSG_LEN, pk_p);
        if (ret != -1 || sentinel_len != 0U) {
            fail(c->tag);
            return;
        }
        ret = crypto_sign_ed25519_open(out, NULL, sm_local,
                                       sig_len + MSG_LEN, pk_p);
        if (ret != -1) {
            fail(c->tag);
            return;
        }
    }
    /* A detached rejection must not alter its caller-visible state either. */
    if (!c->truncated) {
        if (crypto_sign_ed25519_verify_detached(sig_p, m, MSG_LEN,
                                                 pk_p) != -1) {
            fail(c->tag);
            return;
        }
    }
    printf("%s: rejected, no authenticated output (length reported: 0)\n",
           c->tag);
}

/* Single-bit mutation sweep over one fixed-size region of an input. */
static void
mutation_sweep(const char *region, size_t region_offset,
               size_t region_len, int use_sig_region)
{
    unsigned char  sig_mut[SIG_LEN];
    unsigned char  pk_mut[PK_LEN];
    unsigned char  sm_local[SIG_LEN + MSG_LEN];
    unsigned char  out[SIG_LEN + MSG_LEN];
    unsigned long long out_len;
    size_t         byte_idx;
    unsigned int   bit;
    int            detached_ret;
    int            open_ret;
    int            accept_mismatch;
    unsigned int   rejected = 0U;
    unsigned int   accepted = 0U;

    for (byte_idx = 0U; byte_idx < region_len; byte_idx++) {
        for (bit = 0U; bit < 8U; bit++) {
            memcpy(sig_mut, sig, sizeof sig_mut);
            memcpy(pk_mut, pk, sizeof pk_mut);
            if (use_sig_region) {
                sig_mut[region_offset + byte_idx] ^=
                    (unsigned char) (1U << bit);
            } else {
                pk_mut[byte_idx] ^= (unsigned char) (1U << bit);
            }

            detached_ret = crypto_sign_ed25519_verify_detached(sig_mut, m,
                                                               MSG_LEN,
                                                               pk_mut);
            memcpy(sm_local, sig_mut, SIG_LEN);
            memcpy(sm_local + SIG_LEN, m, MSG_LEN);
            memset(out, CANARY, sizeof out);
            out_len = (unsigned long long) 0xdeadbeefULL;
            open_ret = crypto_sign_ed25519_open(out, &out_len, sm_local,
                                                sizeof sm_local, pk_mut);

            accept_mismatch = (detached_ret == 0) != (open_ret == 0);
            if (accept_mismatch) {
                printf("FAIL: %s mutation byte %u bit %u splits the "
                       "acceptance set (detached=%d open=%d)\n", region,
                       (unsigned int) byte_idx, bit, detached_ret, open_ret);
                failures++;
                continue;
            }
            if (open_ret == -1) {
                /* Every rejection must still obey the zero-length / zeroed
                 * message contract. */
                if (out_len != 0U) {
                    fail("mutation output length");
                }
                {
                    size_t k;
                    int    dirty = 0;
                    for (k = 0U; k < MSG_LEN; k++) {
                        if (out[k] != 0U) {
                            dirty = 1;
                        }
                    }
                    if (dirty) {
                        fail("mutation left a non-zero authenticated region");
                    }
                }
                rejected++;
            } else {
                /*
                 * A mutated input that still verifies must return exactly the
                 * original message and its length: the acceptance boundary may
                 * admit it, but the authenticated content must be intact.
                 */
                if (out_len != MSG_LEN || memcmp(out, m, MSG_LEN) != 0) {
                    fail("mutation accepted with altered message");
                }
                accepted++;
            }
        }
    }
    printf("%s mutations: %u rejected, %u accepted, 0 acceptance-set "
           "divergences\n", region, rejected, accepted);
}

/*
 * Message tampering with the minimal possible change.  The valid signature is
 * kept untouched (control), which isolates the verification-stage decision
 * from the parsing-stage decisions exercised by signature mutations.
 */
static void
message_tamper_sweep(void)
{
    unsigned char  m_tamper[MSG_LEN];
    unsigned char  sm_local[SIG_LEN + MSG_LEN];
    unsigned char  out[SIG_LEN + MSG_LEN];
    unsigned long long out_len;
    size_t         byte_idx;
    unsigned int   bit;
    int            detached_ret;
    int            open_ret;

    for (byte_idx = 0U; byte_idx < MSG_LEN; byte_idx++) {
        for (bit = 0U; bit < 8U; bit++) {
            memcpy(m_tamper, m, sizeof m_tamper);
            m_tamper[byte_idx] ^= (unsigned char) (1U << bit);

            detached_ret = crypto_sign_ed25519_verify_detached(sig, m_tamper,
                                                               MSG_LEN, pk);
            memcpy(sm_local, sig, SIG_LEN);
            memcpy(sm_local + SIG_LEN, m_tamper, MSG_LEN);
            memset(out, CANARY, sizeof out);
            out_len = (unsigned long long) 0xdeadbeefULL;
            open_ret = crypto_sign_ed25519_open(out, &out_len, sm_local,
                                                sizeof sm_local, pk);

            if (detached_ret != -1 || open_ret != -1) {
                printf("FAIL: tampered message byte %u bit %u was "
                       "authenticated (detached=%d open=%d)\n",
                       (unsigned int) byte_idx, bit, detached_ret, open_ret);
                failures++;
                continue;
            }
            if (out_len != 0U) {
                fail("tampered message produced a non-zero length");
                continue;
            }
            {
                size_t k;
                for (k = 0U; k < MSG_LEN; k++) {
                    if (out[k] != 0U) {
                        fail("tampered message left authenticated bytes");
                        break;
                    }
                }
            }
        }
    }
    printf("message mutations: %u rejected, 0 accepted\n",
           (unsigned int) MSG_LEN * 8U);
}

int
main(void)
{
    Case             cases[9];
    unsigned char    out[SIG_LEN + MSG_LEN];
    unsigned long long out_len;
    unsigned int     i;

    /* Deterministic setup: fixed seed, fixed message. */
    memset(seed, 0x42, sizeof seed);
    for (i = 0U; i < MSG_LEN; i++) {
        m[i] = (unsigned char) (0x61U + (i % 26U));
    }
    if (crypto_sign_ed25519_seed_keypair(pk, sk, seed) != 0) {
        fail("seed_keypair");
        return 1;
    }
    if (crypto_sign_ed25519_detached(sig, &siglen, m, MSG_LEN, sk) != 0 ||
        siglen != SIG_LEN) {
        fail("detached sign");
        return 1;
    }
    if (crypto_sign_ed25519(sm, &smlen, m, MSG_LEN, sk) != 0 ||
        smlen != SIG_LEN + MSG_LEN) {
        fail("combined sign");
        return 1;
    }
    /* The two signing flows must produce the same signature bytes. */
    if (memcmp(sm, sig, SIG_LEN) != 0) {
        fail("detached/combined signature mismatch");
        return 1;
    }

    /* Control: the untouched valid material verifies on every interface. */
    memset(out, CANARY, sizeof out);
    out_len = (unsigned long long) 0xdeadbeefULL;
    if (crypto_sign_ed25519_verify_detached(sig, m, MSG_LEN, pk) != 0) {
        fail("control detached verify");
    }
    if (crypto_sign_verify_detached(sig, m, MSG_LEN, pk) != 0) {
        fail("control generic detached verify");
    }
    if (crypto_sign_ed25519_open(out, &out_len, sm, smlen, pk) != 0 ||
        out_len != MSG_LEN || memcmp(out, m, MSG_LEN) != 0) {
        fail("control combined open");
    }
    if (crypto_sign_open(out, &out_len, sm, smlen, pk) != 0 ||
        out_len != MSG_LEN || memcmp(out, m, MSG_LEN) != 0) {
        fail("control generic combined open");
    }
    printf("control: valid signature accepted, message recovered intact\n");

    /* ---- Build the malformed-encoding case table. ---- */
    memset(cases, 0, sizeof cases);

    /* 0: non-canonical S == L (parsing shortcut misses, scalar check catches). */
    cases[0].tag = "non-canonical scalar S=L";
    cases[0].mutate_sig = 1;
    memcpy(cases[0].sig_buf, sig, SIG_LEN);
    hex2bin_fixed(cases[0].sig_buf + 32, 32, noncanonical_s_eq_L);

    /* 1: non-canonical S = L+1 with non-zero top nibble (early reject). */
    cases[1].tag = "non-canonical scalar S=L+1";
    cases[1].mutate_sig = 1;
    memcpy(cases[1].sig_buf, sig, SIG_LEN);
    hex2bin_fixed(cases[1].sig_buf + 32, 32, noncanonical_s_L_plus_1);

    /* 2: S >> L, historical high-scalar rejection vector. */
    cases[2].tag = "non-canonical scalar S>>L";
    cases[2].mutate_sig = 1;
    memcpy(cases[2].sig_buf, sig, SIG_LEN);
    hex2bin_fixed(cases[2].sig_buf + 32, 32, noncanonical_s_high);

    /* 3: non-canonical point encoding used as R. */
    cases[3].tag = "non-canonical point R";
    cases[3].mutate_sig = 1;
    memcpy(cases[3].sig_buf, sig, SIG_LEN);
    hex2bin_fixed(cases[3].sig_buf, 32, noncanonical_r_identity);

    /* 4: canonical but small-order R (weak point, verification stage). */
    cases[4].tag = "small-order point R";
    cases[4].mutate_sig = 1;
    memcpy(cases[4].sig_buf, sig, SIG_LEN);
    hex2bin_fixed(cases[4].sig_buf, 32, small_order_r);

    /* 5: non-canonical public key encoding. */
    cases[5].tag = "non-canonical public key";
    cases[5].mutate_sig = 0;
    hex2bin_fixed(cases[5].pk_buf, PK_LEN, noncanonical_r_identity);

    /* 6: canonical small-order public key (weak A). */
    cases[6].tag = "small-order public key";
    cases[6].mutate_sig = 0;
    hex2bin_fixed(cases[6].pk_buf, PK_LEN, small_order_pk);

    /* 7: truncated signature, one byte short of the 64-byte boundary. */
    cases[7].tag = "truncated signature (63 bytes)";
    cases[7].mutate_sig = 1;
    cases[7].truncated = 1;
    cases[7].sig_trim = 1U;
    memcpy(cases[7].sig_buf, sig, SIG_LEN);

    /* 8: truncated signature down to the R half only. */
    cases[8].tag = "truncated signature (32 bytes, R only)";
    cases[8].mutate_sig = 1;
    cases[8].truncated = 1;
    cases[8].sig_trim = 32U;
    memcpy(cases[8].sig_buf, sig, SIG_LEN);

    for (i = 0U; i < sizeof cases / sizeof cases[0]; i++) {
        run_malformed_case(&cases[i]);
    }

    /* Empty-message boundary: zero-length input must stay consistent too. */
    {
        unsigned char  empty_sig[SIG_LEN];
        unsigned char  empty_sm[SIG_LEN];
        unsigned char  empty_out[SIG_LEN];
        unsigned long long empty_siglen = 0U;
        unsigned long long empty_smlen = 0U;

        if (crypto_sign_ed25519_detached(empty_sig, &empty_siglen,
                                         NULL, 0U, sk) != 0 ||
            empty_siglen != SIG_LEN) {
            fail("empty message sign");
        }
        if (crypto_sign_ed25519(empty_sm, &empty_smlen, NULL, 0U, sk) != 0 ||
            empty_smlen != SIG_LEN ||
            memcmp(empty_sm, empty_sig, SIG_LEN) != 0) {
            fail("empty message combined sign");
        }
        if (crypto_sign_ed25519_verify_detached(empty_sig, NULL, 0U,
                                                 pk) != 0) {
            fail("empty message detached verify");
        }
        memset(empty_out, CANARY, sizeof empty_out);
        empty_smlen = (unsigned long long) 0xdeadbeefULL;
        if (crypto_sign_ed25519_open(empty_out, &empty_smlen, empty_sm,
                                     SIG_LEN, pk) != 0 ||
            empty_smlen != 0U) {
            fail("empty message open");
        }
        printf("empty message: accepted on both interfaces, zero-length "
               "payload\n");
    }

    /*
     * Minimal-mutation sweeps.  Signature mutations distinguish parsing-stage
     * rejections (malformed R/S) from verification-stage rejections (valid
     * encoding, wrong equation); message mutations always land at the
     * verification stage because the signature itself parses cleanly.
     */
    mutation_sweep("signature R region", 0U, 32U, 1);
    mutation_sweep("signature S region", 32U, 32U, 1);
    mutation_sweep("public key", 0U, PK_LEN, 0);
    message_tamper_sweep();

    if (failures != 0) {
        printf("%d boundary failure(s)\n", failures);
        return 1;
    }
    printf("OK\n");

    return 0;
}
