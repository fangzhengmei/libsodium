
#define TEST_NAME "secretstream_xchacha20poly1305"
#include "cmptest.h"

#define SS_RT_M_MAX      120U
#define SS_RT_AD_MAX     32U
#define SS_RT_CHUNK_MAX  (SS_RT_M_MAX + crypto_secretstream_xchacha20poly1305_ABYTES)
#define SS_RT_CANARY     0xa5

static void
ss_rt_fill(unsigned char *p, size_t len, unsigned char v)
{
    memset(p, v, len);
}

/* check that every byte of an output buffer still holds the canary, i.e.
 * the library never wrote an unauthenticated plaintext into it */
static void
ss_rt_check_canary(const unsigned char *p, size_t len)
{
    size_t i;

    for (i = 0U; i < len; i++) {
        assert(p[i] == SS_RT_CANARY);
    }
}

/* Expect pull() to reject the chunk.  This verifies the four guarantees of
 * an authentication failure: -1 is returned, the message length stays zero,
 * the tag is the 0xff sentinel set on entry, no plaintext ever reaches the
 * output buffer, and the receiver state is left completely untouched so that
 * the next legitimate chunk can still be accepted. */
static void
ss_rt_expect_pull_fail(crypto_secretstream_xchacha20poly1305_state *state,
                       const unsigned char *c, unsigned long long clen,
                       const unsigned char *ad, unsigned long long adlen,
                       const crypto_secretstream_xchacha20poly1305_state *state_before)
{
    crypto_secretstream_xchacha20poly1305_state state_after;
    unsigned char                               m_out[SS_RT_M_MAX];
    unsigned long long                          mlen = 0x9a9b9c9dULL;
    unsigned char                               tag = 0x11;

    ss_rt_fill(m_out, sizeof m_out, SS_RT_CANARY);
    state_after = *state;

    int r = crypto_secretstream_xchacha20poly1305_pull
        (state, m_out, &mlen, &tag, c, clen, ad, adlen);
    assert(r == -1);
    /* no unauthenticated plaintext is exposed to the caller */
    ss_rt_check_canary(m_out, sizeof m_out);
    assert(mlen == 0U);
    assert(tag == 0xff);
    /* the authentication state must not have advanced */
    assert(memcmp(&state_after, state, sizeof state_after) == 0);
    assert(memcmp(state_before, state, sizeof *state_before) == 0);
}

/* Expect pull() to accept the chunk and verify the recovered plaintext and
 * tag.  Also records the new state in state_after so the caller can observe
 * that a successful pull deterministically advances the state. */
static void
ss_rt_expect_pull_ok(crypto_secretstream_xchacha20poly1305_state *state,
                     const unsigned char *c, unsigned long long clen,
                     const unsigned char *ad, unsigned long long adlen,
                     const unsigned char *m_expected, unsigned long long m_expected_len,
                     unsigned char tag_expected,
                     crypto_secretstream_xchacha20poly1305_state *state_before,
                     crypto_secretstream_xchacha20poly1305_state *state_after)
{
    unsigned char      m_out[SS_RT_M_MAX];
    unsigned long long mlen = 0U;
    unsigned char      tag = 0xff;

    ss_rt_fill(m_out, sizeof m_out, SS_RT_CANARY);
    if (state_before != NULL) {
        *state_before = *state;
    }
    int r = crypto_secretstream_xchacha20poly1305_pull
        (state, m_out, &mlen, &tag, c, clen, ad, adlen);
    assert(r == 0);
    assert(mlen == m_expected_len);
    assert(tag == tag_expected);
    assert(memcmp(m_out, m_expected, (size_t) m_expected_len) == 0);
    /* only the plaintext prefix is written; the rest of the buffer is
     * untouched, proving the library decrypts after, not before, the MAC
     * check */
    ss_rt_check_canary(m_out + m_expected_len,
                       sizeof m_out - (size_t) m_expected_len);
    assert(memcmp(state, state_before, sizeof *state) != 0);
    if (state_after != NULL) {
        *state_after = *state;
    }
}

/* Receiver-side behaviour in the presence of malicious chunks, reordered and
 * replayed messages, forged tags, and REKEY/FINAL boundaries. */
static void
secretstream_xchacha20poly1305_receiver_security(void)
{
    crypto_secretstream_xchacha20poly1305_state push_state, pull_state;
    crypto_secretstream_xchacha20poly1305_state state_before, state_after;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned char k[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char ad[SS_RT_AD_MAX];
    unsigned char m1[SS_RT_M_MAX], m2[SS_RT_M_MAX], m3[SS_RT_M_MAX];
    unsigned char m4[SS_RT_M_MAX];
    unsigned char c1[SS_RT_CHUNK_MAX], c2[SS_RT_CHUNK_MAX];
    unsigned char c3[SS_RT_CHUNK_MAX], c4[SS_RT_CHUNK_MAX];
    unsigned char bad[SS_RT_CHUNK_MAX];
    const size_t  m1_len = 37U;
    const size_t  m2_len = 72U;
    const size_t  m3_len = 15U;
    const size_t  m4_len = 0U;   /* empty message */
    const size_t  ad_len = 13U;
    unsigned long long c1_len, c2_len, c3_len, c4_len;
    unsigned char      tag;

    crypto_secretstream_xchacha20poly1305_keygen(k);
    randombytes_buf(ad, ad_len);
    randombytes_buf(m1, m1_len);
    randombytes_buf(m2, m2_len);
    randombytes_buf(m3, m3_len);

    /* stream 1: MESSAGE, REKEY, MESSAGE, FINAL, all authenticated with ad */

    assert(crypto_secretstream_xchacha20poly1305_init_push
           (&push_state, header, k) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c1, &c1_len, m1, m1_len, ad, ad_len,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c2, &c2_len, m2, m2_len, ad, ad_len,
            crypto_secretstream_xchacha20poly1305_TAG_REKEY) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c3, &c3_len, m3, m3_len, ad, ad_len,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c4, &c4_len, m4, m4_len, ad, ad_len,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL) == 0);
    assert(c1_len == m1_len + crypto_secretstream_xchacha20poly1305_ABYTES);
    assert(c2_len == m2_len + crypto_secretstream_xchacha20poly1305_ABYTES);
    assert(c3_len == m3_len + crypto_secretstream_xchacha20poly1305_ABYTES);
    assert(c4_len == m4_len + crypto_secretstream_xchacha20poly1305_ABYTES);

    assert(crypto_secretstream_xchacha20poly1305_init_pull
           (&pull_state, header, k) == 0);

    /* out-of-order delivery: c2 is presented before c1 */
    state_before = pull_state;
    ss_rt_expect_pull_fail(&pull_state, c2, c2_len, ad, ad_len, &state_before);
    /* the legitimate c1 must still be accepted and the stream recover */
    ss_rt_expect_pull_ok(&pull_state, c1, c1_len, ad, ad_len, m1, m1_len,
                         crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
                         &state_before, &state_after);

    /* replay / duplicate delivery of the already accepted c1 */
    state_before = pull_state;
    ss_rt_expect_pull_fail(&pull_state, c1, c1_len, ad, ad_len, &state_before);
    /* normal flow resumes with the rekey-tagged chunk */
    ss_rt_expect_pull_ok(&pull_state, c2, c2_len, ad, ad_len, m2, m2_len,
                         crypto_secretstream_xchacha20poly1305_TAG_REKEY,
                         &state_before, &state_after);

    /* forged tag byte: c3's encrypted tag is flipped, invalidating the MAC */
    memcpy(bad, c3, (size_t) c3_len);
    bad[0] ^= 0x01;
    state_before = pull_state;
    ss_rt_expect_pull_fail(&pull_state, bad, c3_len, ad, ad_len, &state_before);
    /* the genuine c3, on the post-rekey key, still decrypts correctly */
    ss_rt_expect_pull_ok(&pull_state, c3, c3_len, ad, ad_len, m3, m3_len,
                         crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
                         &state_before, &state_after);

    /* tampered ciphertext body */
    memcpy(bad, c4, (size_t) c4_len);
    bad[1] ^= 0x04;
    state_before = pull_state;
    ss_rt_expect_pull_fail(&pull_state, bad, c4_len, ad, ad_len, &state_before);

    /* tampered authentication tag (last 16 bytes carry the Poly1305 MAC) */
    memcpy(bad, c4, (size_t) c4_len);
    bad[c4_len - 1U] ^= 0x80;
    ss_rt_expect_pull_fail(&pull_state, bad, c4_len, ad, ad_len, &state_before);

    /* wrong / missing associated data */
    ss_rt_expect_pull_fail(&pull_state, c4, c4_len, NULL, 0U, &state_before);
    memcpy(bad, ad, ad_len);
    bad[0] ^= 0x01;
    ss_rt_expect_pull_fail(&pull_state, c4, c4_len, bad, ad_len, &state_before);

    /* truncated chunks, including a zero-length input */
    ss_rt_expect_pull_fail
        (&pull_state, c4,
         crypto_secretstream_xchacha20poly1305_ABYTES - 1U,
         ad, ad_len, &state_before);
    ss_rt_expect_pull_fail(&pull_state, c4, 0U, ad, ad_len, &state_before);

    /* a rejected chunk must not release plaintext even into NULL sinks */
    memcpy(bad, c4, (size_t) c4_len);
    bad[c4_len - 1U] ^= 0x01;
    {
        crypto_secretstream_xchacha20poly1305_state state_copy;

        state_copy = pull_state;
        assert(crypto_secretstream_xchacha20poly1305_pull
               (&pull_state, NULL, NULL, NULL, bad, c4_len, ad,
                ad_len) == -1);
        assert(memcmp(&state_copy, &pull_state, sizeof state_copy) == 0);
    }

    /* the stream remains fully usable: the untouched state still accepts c4,
     * including its empty plaintext and FINAL tag */
    ss_rt_expect_pull_ok(&pull_state, c4, c4_len, ad, ad_len, m4, m4_len,
                         crypto_secretstream_xchacha20poly1305_TAG_FINAL,
                         &state_before, &state_after);

    /* FINAL carries the REKEY bit, so the key rotated: every earlier chunk is
     * now a stale replay and must keep failing without changing the state */
    state_before = pull_state;
    ss_rt_expect_pull_fail(&pull_state, c3, c3_len, ad, ad_len, &state_before);
    ss_rt_expect_pull_fail(&pull_state, c4, c4_len, ad, ad_len, &state_before);

    /* stream 2: REKEY immediately followed by FINAL (no gap, no overlap),
     * covering both directions of the boundary */

    assert(crypto_secretstream_xchacha20poly1305_init_push
           (&push_state, header, k) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c1, &c1_len, m1, m1_len, NULL, 0U,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c2, &c2_len, m2, m2_len, NULL, 0U,
            crypto_secretstream_xchacha20poly1305_TAG_REKEY) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c3, &c3_len, m3, m3_len, NULL, 0U,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL) == 0);

    assert(crypto_secretstream_xchacha20poly1305_init_pull
           (&pull_state, header, k) == 0);
    ss_rt_expect_pull_ok(&pull_state, c1, c1_len, NULL, 0U, m1, m1_len,
                         crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
                         &state_before, &state_after);

    /* tamper with the REKEY chunk: the receiver must neither rekey nor
     * advance, otherwise it would lose synchronization with the sender */
    memcpy(bad, c2, (size_t) c2_len);
    bad[2] ^= 0x02;
    state_before = pull_state;
    ss_rt_expect_pull_fail(&pull_state, bad, c2_len, NULL, 0U, &state_before);
    ss_rt_expect_pull_ok(&pull_state, c2, c2_len, NULL, 0U, m2, m2_len,
                         crypto_secretstream_xchacha20poly1305_TAG_REKEY,
                         &state_before, &state_after);

    /* tamper with the FINAL chunk directly adjacent to the REKEY boundary */
    memcpy(bad, c3, (size_t) c3_len);
    bad[c3_len - 1U] ^= 0x08;
    state_before = pull_state;
    ss_rt_expect_pull_fail(&pull_state, bad, c3_len, NULL, 0U, &state_before);
    ss_rt_expect_pull_ok(&pull_state, c3, c3_len, NULL, 0U, m3, m3_len,
                         crypto_secretstream_xchacha20poly1305_TAG_FINAL,
                         &state_before, &state_after);

    /* stream-end constraints are the caller's job: the primitive only
     * authenticates chunks, it does not remember that FINAL was seen.  The
     * sender keeps emitting on the rotated key; the library still accepts the
     * fresh, authentic chunk, while an application-side FINAL policy is what
     * actually closes the stream. */
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c4, &c4_len, m1, m1_len, NULL, 0U,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) == 0);
    {
        unsigned char      m_out[SS_RT_M_MAX];
        unsigned long long mlen;
        unsigned char      observed_tag;

        /* layer 1, provided by the library: the chunk is fully authenticated */
        state_before = pull_state;
        assert(crypto_secretstream_xchacha20poly1305_pull
               (&pull_state, m_out, &mlen, &observed_tag, c4, c4_len,
                NULL, 0U) == 0);
        assert(mlen == m1_len);
        assert(memcmp(m_out, m1, m1_len) == 0);
        assert(observed_tag ==
               crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        assert(memcmp(&state_before, &pull_state, sizeof state_before) != 0);

        /* layer 2, provided by the caller: after observing FINAL on c3 it is
         * the application's responsibility to refuse any further chunk; the
         * primitive enforces no such end-of-stream state */
        assert(observed_tag !=
               crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        (void) state_after;
    }

    /* stream 3: legitimate early FINAL, including an empty-message chunk */

    assert(crypto_secretstream_xchacha20poly1305_init_push
           (&push_state, header, k) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c1, &c1_len, m1, m1_len, ad, ad_len,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c2, &c2_len, m4, m4_len, ad, ad_len,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL) == 0);

    assert(crypto_secretstream_xchacha20poly1305_init_pull
           (&pull_state, header, k) == 0);
    ss_rt_expect_pull_ok(&pull_state, c1, c1_len, ad, ad_len, m1, m1_len,
                         crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
                         &state_before, &state_after);
    /* early end of stream: an empty message with a FINAL tag is accepted */
    ss_rt_expect_pull_ok(&pull_state, c2, c2_len, ad, ad_len, m4, m4_len,
                         crypto_secretstream_xchacha20poly1305_TAG_FINAL,
                         &state_before, &state_after);
    /* replaying the FINAL chunk after its key rotation fails, again without
     * advancing the state */
    state_before = pull_state;
    ss_rt_expect_pull_fail(&pull_state, c2, c2_len, ad, ad_len, &state_before);

    /* an out-of-band rekey on both sides keeps the stream synchronized, and
     * a chunk presented before the matching rekey is rejected harmlessly */
    assert(crypto_secretstream_xchacha20poly1305_init_push
           (&push_state, header, k) == 0);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c1, &c1_len, m1, m1_len, NULL, 0U,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) == 0);
    crypto_secretstream_xchacha20poly1305_rekey(&push_state);
    assert(crypto_secretstream_xchacha20poly1305_push
           (&push_state, c2, &c2_len, m2, m2_len, NULL, 0U,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) == 0);

    assert(crypto_secretstream_xchacha20poly1305_init_pull
           (&pull_state, header, k) == 0);
    ss_rt_expect_pull_ok(&pull_state, c1, c1_len, NULL, 0U, m1, m1_len,
                         crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
                         &state_before, &state_after);
    state_before = pull_state;
    ss_rt_expect_pull_fail(&pull_state, c2, c2_len, NULL, 0U, &state_before);
    crypto_secretstream_xchacha20poly1305_rekey(&pull_state);
    ss_rt_expect_pull_ok(&pull_state, c2, c2_len, NULL, 0U, m2, m2_len,
                         crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
                         &state_before, &state_after);
}

int
main(void)
{
    crypto_secretstream_xchacha20poly1305_state *state, *statesave;
    crypto_secretstream_xchacha20poly1305_state state_copy;
    unsigned char      *ad;
    unsigned char      *header;
    unsigned char      *k;
    unsigned char      *c1, *c2, *c3, *csave;
    unsigned char      *m1, *m2, *m3;
    unsigned char      *m1_, *m2_, *m3_;
    unsigned long long  res_len;
    size_t              ad_len;
    size_t              m1_len, m2_len, m3_len;
    int                 ret;
    unsigned char       tag;

    state = (crypto_secretstream_xchacha20poly1305_state *)
        sodium_malloc(crypto_secretstream_xchacha20poly1305_statebytes());
    statesave = (crypto_secretstream_xchacha20poly1305_state *)
        sodium_malloc(crypto_secretstream_xchacha20poly1305_statebytes());
    header = (unsigned char *)
        sodium_malloc(crypto_secretstream_xchacha20poly1305_HEADERBYTES);

    ad_len = randombytes_uniform(100);
    m1_len = randombytes_uniform(1000);
    m2_len = randombytes_uniform(1000);
    m3_len = randombytes_uniform(1000);

    c1 = (unsigned char *)
        sodium_malloc(m1_len + crypto_secretstream_xchacha20poly1305_ABYTES);
    c2 = (unsigned char *)
        sodium_malloc(m2_len + crypto_secretstream_xchacha20poly1305_ABYTES);
    c3 = (unsigned char *)
        sodium_malloc(m3_len + crypto_secretstream_xchacha20poly1305_ABYTES);
    csave = (unsigned char *)
        sodium_malloc((m1_len | m2_len | m3_len) + crypto_secretstream_xchacha20poly1305_ABYTES);

    ad  = (unsigned char *) sodium_malloc(ad_len);
    m1  = (unsigned char *) sodium_malloc(m1_len);
    m2  = (unsigned char *) sodium_malloc(m2_len);
    m3  = (unsigned char *) sodium_malloc(m3_len);
    m1_ = (unsigned char *) sodium_malloc(m1_len);
    m2_ = (unsigned char *) sodium_malloc(m2_len);
    m3_ = (unsigned char *) sodium_malloc(m3_len);

    randombytes_buf(ad, ad_len);

    randombytes_buf(m1, m1_len);
    memcpy(m1_, m1, m1_len);
    randombytes_buf(m2, m2_len);
    memcpy(m2_, m2, m2_len);
    randombytes_buf(m3, m3_len);
    memcpy(m3_, m3, m3_len);

    k = (unsigned char *)
        sodium_malloc(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    crypto_secretstream_xchacha20poly1305_keygen(k);

    /* push */

    ret = crypto_secretstream_xchacha20poly1305_init_push(state, header, k);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c1, &res_len, m1, m1_len, NULL, 0, 0);
    assert(ret == 0);
    assert(res_len == m1_len + crypto_secretstream_xchacha20poly1305_ABYTES);

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c2, NULL, m2, m2_len, ad, 0, 0);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c3, NULL, m3, m3_len, ad, ad_len,
         crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    assert(ret == 0);

    /* pull */

    ret = crypto_secretstream_xchacha20poly1305_init_pull(state, header, k);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m1, &res_len, &tag,
         c1, m1_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == 0);
    assert(tag == 0);
    assert(memcmp(m1, m1_, m1_len) == 0);
    assert(res_len == m1_len);

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag,
         c2, m2_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == 0);
    assert(tag == 0);
    assert(memcmp(m2, m2_, m2_len) == 0);

    if (ad_len > 0) {
        ret = crypto_secretstream_xchacha20poly1305_pull
            (state, m3, NULL, &tag,
             c3, m3_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
        assert(ret == -1);
    }
    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m3, NULL, &tag,
         c3, m3_len + crypto_secretstream_xchacha20poly1305_ABYTES, ad, ad_len);
    assert(ret == 0);
    assert(tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    assert(memcmp(m3, m3_, m3_len) == 0);

    /* previous with FINAL tag */

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m3, NULL, &tag,
         c3, m3_len + crypto_secretstream_xchacha20poly1305_ABYTES, ad, ad_len);
    assert(ret == -1);

    /* previous without a tag */

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag,
         c2, m2_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == -1);

    /* short ciphertext */

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag, c2,
         randombytes_uniform(crypto_secretstream_xchacha20poly1305_ABYTES),
         NULL, 0);
    assert(ret == -1);
    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag, c2, 0, NULL, 0);
    assert(ret == -1);

    /* empty ciphertext */

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag, c2,
         crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == -1);

    /* without explicit rekeying */

    ret = crypto_secretstream_xchacha20poly1305_init_push(state, header, k);
    assert(ret == 0);
    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c1, NULL, m1, m1_len, NULL, 0, 0);
    assert(ret == 0);
    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c2, NULL, m2, m2_len, NULL, 0, 0);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_init_pull(state, header, k);
    assert(ret == 0);
    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m1, NULL, &tag,
         c1, m1_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == 0);
    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag,
         c2, m2_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == 0);

    /* with explicit rekeying */

    ret = crypto_secretstream_xchacha20poly1305_init_push(state, header, k);
    assert(ret == 0);
    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c1, NULL, m1, m1_len, NULL, 0, 0);
    assert(ret == 0);

    crypto_secretstream_xchacha20poly1305_rekey(state);

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c2, NULL, m2, m2_len, NULL, 0, 0);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_init_pull(state, header, k);
    assert(ret == 0);
    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m1, NULL, &tag,
         c1, m1_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag,
         c2, m2_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == -1);

    crypto_secretstream_xchacha20poly1305_rekey(state);

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag,
         c2, m2_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == 0);

    /* with explicit rekeying using TAG_REKEY */

    ret = crypto_secretstream_xchacha20poly1305_init_push(state, header, k);
    assert(ret == 0);

    memcpy(statesave, state, sizeof *state);

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c1, NULL, m1, m1_len, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_REKEY);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c2, NULL, m2, m2_len, NULL, 0, 0);
    assert(ret == 0);

    memcpy(csave, c2, m2_len + crypto_secretstream_xchacha20poly1305_ABYTES);

    ret = crypto_secretstream_xchacha20poly1305_init_pull(state, header, k);
    assert(ret == 0);
    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m1, NULL, &tag,
         c1, m1_len + crypto_secretstream_xchacha20poly1305_ABYTES, &tag, 0);
    assert(ret == 0);
    assert(tag == crypto_secretstream_xchacha20poly1305_TAG_REKEY);

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag,
         c2, m2_len + crypto_secretstream_xchacha20poly1305_ABYTES, &tag, 0);
    assert(ret == 0);
    assert(tag == 0);

    memcpy(state, statesave, sizeof *state);

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c1, NULL, m1, m1_len, NULL, 0, 0);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c2, NULL, m2, m2_len, NULL, 0, 0);
    assert(ret == 0);

    assert(memcmp(csave, c2, m2_len + crypto_secretstream_xchacha20poly1305_ABYTES) != 0);

    /* New stream */

    ret = crypto_secretstream_xchacha20poly1305_init_push(state, header, k);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c1, &res_len, m1, m1_len, NULL, 0,
         crypto_secretstream_xchacha20poly1305_TAG_PUSH);
    assert(ret == 0);
    assert(res_len == m1_len + crypto_secretstream_xchacha20poly1305_ABYTES);

    /* Force a counter overflow and check that the key has been updated
     * even though the tag was not changed to REKEY */

    memset(state->nonce, 0xff, 4U);
    state_copy = *state;

    ret = crypto_secretstream_xchacha20poly1305_push
        (state, c2, NULL, m2, m2_len, ad, 0, 0);
    assert(ret == 0);

    assert(memcmp(state_copy.k, state->k, sizeof state->k) != 0);
    assert(memcmp(state_copy.nonce, state->nonce, sizeof state->nonce) != 0);
    assert(state->nonce[0] == 1U);
    assert(sodium_is_zero(state->nonce + 1, 3U));

    ret = crypto_secretstream_xchacha20poly1305_init_pull(state, header, k);
    assert(ret == 0);

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m1, &res_len, &tag,
         c1, m1_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == 0);
    assert(tag == crypto_secretstream_xchacha20poly1305_TAG_PUSH);
    assert(memcmp(m1, m1_, m1_len) == 0);
    assert(res_len == m1_len);

    memset(state->nonce, 0xff, 4U);

    ret = crypto_secretstream_xchacha20poly1305_pull
        (state, m2, NULL, &tag,
         c2, m2_len + crypto_secretstream_xchacha20poly1305_ABYTES, NULL, 0);
    assert(ret == 0);
    assert(tag == 0);
    assert(memcmp(m2, m2_, m2_len) == 0);

    /* receiver security: malicious chunks, reordering, replays and
     * REKEY/FINAL boundaries must never desynchronize the state or leak
     * unauthenticated plaintext */
    secretstream_xchacha20poly1305_receiver_security();

    sodium_free(m3_);
    sodium_free(m2_);
    sodium_free(m1_);
    sodium_free(m3);
    sodium_free(m2);
    sodium_free(m1);
    sodium_free(ad);
    sodium_free(csave);
    sodium_free(c3);
    sodium_free(c2);
    sodium_free(c1);
    sodium_free(k);
    sodium_free(header);
    sodium_free(statesave);
    sodium_free(state);

    assert(crypto_secretstream_xchacha20poly1305_abytes() ==
           crypto_secretstream_xchacha20poly1305_ABYTES);
    assert(crypto_secretstream_xchacha20poly1305_headerbytes() ==
           crypto_secretstream_xchacha20poly1305_HEADERBYTES);
    assert(crypto_secretstream_xchacha20poly1305_keybytes() ==
           crypto_secretstream_xchacha20poly1305_KEYBYTES);
    assert(crypto_secretstream_xchacha20poly1305_messagebytes_max() ==
           crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX);

    assert(crypto_secretstream_xchacha20poly1305_tag_message() ==
           crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
    assert(crypto_secretstream_xchacha20poly1305_tag_push() ==
           crypto_secretstream_xchacha20poly1305_TAG_PUSH);
    assert(crypto_secretstream_xchacha20poly1305_tag_rekey() ==
           crypto_secretstream_xchacha20poly1305_TAG_REKEY);
    assert(crypto_secretstream_xchacha20poly1305_tag_final() ==
           crypto_secretstream_xchacha20poly1305_TAG_FINAL);

    printf("OK\n");

    return 0;
}
