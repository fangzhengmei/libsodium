
#define TEST_NAME "aead_edge"
#include "cmptest.h"

/*
 * Memory-safety tests for AEAD decryption under abnormal lengths and
 * buffer-edge conditions, covering both the combined and the detached
 * (in-place and separate-buffer) paths of every supported backend:
 *
 * 1. Short ciphertexts (< ABYTES) combined with different AD lengths,
 *    bad tags, in-place aliasing and separate buffers. Buffers are
 *    bracketed by sentinel bytes (and allocated with sodium_malloc(),
 *    which adds guard pages) to detect out-of-bounds accesses on the
 *    failure path, and the reported output length must not be
 *    mistaken for a success indicator.
 *
 * 2. Round trips across backends and boundary buffer layouts: the same
 *    message must yield consistent authentication results, plaintext
 *    and lengths through the combined and detached APIs.
 *
 * 3. After an authentication failure, the output buffer, the returned
 *    length and subsequent calls must not let a caller treat partially
 *    decrypted data as verified.
 */

#define CANARY_LEN   32U
#define CANARY_BYTE  0xa5
#define BODY_BYTE    0x42
#define MAX_MLEN     4099U
#define MAX_ADLEN    256U
#define MAX_ABYTES   32U
#define MAX_KEYBYTES 32U
#define MAX_NPUBBYTES 32U

typedef int (*aead_encrypt_fn)(unsigned char *, unsigned long long *,
                               const unsigned char *, unsigned long long,
                               const unsigned char *, unsigned long long,
                               const unsigned char *, const unsigned char *,
                               const unsigned char *);
typedef int (*aead_encrypt_detached_fn)(unsigned char *, unsigned char *,
                                        unsigned long long *,
                                        const unsigned char *, unsigned long long,
                                        const unsigned char *, unsigned long long,
                                        const unsigned char *, const unsigned char *,
                                        const unsigned char *);
typedef int (*aead_decrypt_fn)(unsigned char *, unsigned long long *,
                               unsigned char *,
                               const unsigned char *, unsigned long long,
                               const unsigned char *, unsigned long long,
                               const unsigned char *, const unsigned char *);
typedef int (*aead_decrypt_detached_fn)(unsigned char *, unsigned char *,
                                        const unsigned char *, unsigned long long,
                                        const unsigned char *,
                                        const unsigned char *, unsigned long long,
                                        const unsigned char *, const unsigned char *);

typedef struct aead_backend_ {
    const char               *name;
    size_t                    keybytes;
    size_t                    npubbytes;
    size_t                    abytes;
    aead_encrypt_fn           encrypt;
    aead_encrypt_detached_fn  encrypt_detached;
    aead_decrypt_fn           decrypt;
    aead_decrypt_detached_fn  decrypt_detached;
    unsigned char             failure_fill; /* byte the output buffer is
                                             * overwritten with on failure */
} aead_backend;

static const aead_backend backends[] = {
    { "chacha20poly1305",
      crypto_aead_chacha20poly1305_KEYBYTES,
      crypto_aead_chacha20poly1305_NPUBBYTES,
      crypto_aead_chacha20poly1305_ABYTES,
      crypto_aead_chacha20poly1305_encrypt,
      crypto_aead_chacha20poly1305_encrypt_detached,
      crypto_aead_chacha20poly1305_decrypt,
      crypto_aead_chacha20poly1305_decrypt_detached,
      0x00 },
    { "chacha20poly1305_ietf",
      crypto_aead_chacha20poly1305_ietf_KEYBYTES,
      crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_chacha20poly1305_ietf_ABYTES,
      crypto_aead_chacha20poly1305_ietf_encrypt,
      crypto_aead_chacha20poly1305_ietf_encrypt_detached,
      crypto_aead_chacha20poly1305_ietf_decrypt,
      crypto_aead_chacha20poly1305_ietf_decrypt_detached,
      0x00 },
    { "xchacha20poly1305_ietf",
      crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_xchacha20poly1305_ietf_ABYTES,
      crypto_aead_xchacha20poly1305_ietf_encrypt,
      crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
      crypto_aead_xchacha20poly1305_ietf_decrypt,
      crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
      0x00 },
    { "aegis128l",
      crypto_aead_aegis128l_KEYBYTES,
      crypto_aead_aegis128l_NPUBBYTES,
      crypto_aead_aegis128l_ABYTES,
      crypto_aead_aegis128l_encrypt,
      crypto_aead_aegis128l_encrypt_detached,
      crypto_aead_aegis128l_decrypt,
      crypto_aead_aegis128l_decrypt_detached,
      0x00 },
    { "aegis256",
      crypto_aead_aegis256_KEYBYTES,
      crypto_aead_aegis256_NPUBBYTES,
      crypto_aead_aegis256_ABYTES,
      crypto_aead_aegis256_encrypt,
      crypto_aead_aegis256_encrypt_detached,
      crypto_aead_aegis256_decrypt,
      crypto_aead_aegis256_decrypt_detached,
      0x00 }
#ifdef crypto_aead_aes256gcm_KEYBYTES
    ,
    { "aes256gcm",
      crypto_aead_aes256gcm_KEYBYTES,
      crypto_aead_aes256gcm_NPUBBYTES,
      crypto_aead_aes256gcm_ABYTES,
      crypto_aead_aes256gcm_encrypt,
      crypto_aead_aes256gcm_encrypt_detached,
      crypto_aead_aes256gcm_decrypt,
      crypto_aead_aes256gcm_decrypt_detached,
      0xd0 }
#endif
};

static unsigned char key[MAX_KEYBYTES];
static unsigned char nonce[MAX_NPUBBYTES];
static unsigned char ad[MAX_ADLEN];
static unsigned char msg[MAX_MLEN];

static int failures;

static void
check_true(int cond, const char *backend, const char *what)
{
    if (! cond) {
        printf("FAIL [%s] %s\n", backend, what);
        failures++;
    }
}

static void
fill_pattern(unsigned char *buf, size_t len, unsigned int seed)
{
    size_t i;

    for (i = 0U; i < len; i++) {
        buf[i] = (unsigned char) (seed + i * 131U + (i >> 3));
    }
}

/* payload of a slab: CANARY_LEN bytes, then payload_len bytes, then CANARY_LEN */
static void
slab_arm(unsigned char *base, size_t payload_len)
{
    memset(base, CANARY_BYTE, CANARY_LEN);
    memset(base + CANARY_LEN + payload_len, CANARY_BYTE, CANARY_LEN);
}

static int
slab_intact(const unsigned char *base, size_t payload_len)
{
    size_t i;

    for (i = 0U; i < CANARY_LEN; i++) {
        if (base[i] != CANARY_BYTE ||
            base[CANARY_LEN + payload_len + i] != CANARY_BYTE) {
            return 0;
        }
    }
    return 1;
}

static int
buffer_is_filled_with(const unsigned char *buf, size_t len, unsigned char byte)
{
    size_t i;

    for (i = 0U; i < len; i++) {
        if (buf[i] != byte) {
            return 0;
        }
    }
    return 1;
}

/*
 * Short ciphertexts (< ABYTES) must be rejected without reading the
 * ciphertext (it points to a guard page), without writing past the
 * output buffer, and with the output length reset to zero.
 */
static void
test_short_ciphertext(const aead_backend *be, unsigned char *c_base,
                      unsigned char *m_base)
{
    static const size_t adlens[] = { 0U, 1U, 16U, 255U };
    unsigned char      *m = m_base + CANARY_LEN;
    unsigned char       mac[MAX_ABYTES];
    unsigned char       dc[1];
    unsigned long long  mlen;
    unsigned long long  clen;
    size_t              adlen;
    size_t              ai;
    int                 ret;

    /* a guaranteed-invalid tag for an empty message */
    be->encrypt_detached(dc, mac, NULL, msg, 0U, NULL, 0U, NULL, nonce, key);
    mac[0] ^= 0x01;

    for (ai = 0U; ai < sizeof adlens / sizeof adlens[0]; ai++) {
        const unsigned char *adp;

        adlen = adlens[ai];
        adp   = adlen > 0U ? ad : NULL;
        for (clen = 0U; clen < be->abytes; clen++) {
            slab_arm(m_base, MAX_MLEN);
            memset(m, BODY_BYTE, MAX_MLEN);
            mlen = 0xdeadbeefULL;
            ret  = be->decrypt(m, &mlen, NULL, guard_page, clen,
                               adp, adlen, nonce, key);
            check_true(ret == -1, be->name,
                       "short ciphertext was not rejected");
            check_true(mlen == 0U, be->name,
                       "short ciphertext: mlen not reset to 0");
            check_true(slab_intact(m_base, MAX_MLEN), be->name,
                       "short ciphertext: output buffer canaries damaged");

            /* in-place aliasing on the failure path */
            slab_arm(m_base, MAX_MLEN);
            memset(m, BODY_BYTE, MAX_MLEN);
            mlen = 0xdeadbeefULL;
            ret  = be->decrypt(m, &mlen, NULL, m, clen,
                               adp, adlen, nonce, key);
            check_true(ret == -1, be->name,
                       "in-place short ciphertext was not rejected");
            check_true(mlen == 0U, be->name,
                       "in-place short ciphertext: mlen not reset to 0");
            check_true(slab_intact(m_base, MAX_MLEN), be->name,
                       "in-place short ciphertext: canaries damaged");
        }

        /* detached path: empty ciphertext at a guard page, bad tag */
        slab_arm(m_base, MAX_MLEN);
        memset(m, BODY_BYTE, MAX_MLEN);
        ret = be->decrypt_detached(m, NULL, guard_page, 0U, mac,
                                   adp, adlen, nonce, key);
        check_true(ret == -1, be->name,
                   "detached empty ciphertext with bad tag not rejected");
        check_true(slab_intact(m_base, MAX_MLEN), be->name,
                   "detached empty ciphertext: canaries damaged");

        /* verification-only (m == NULL) with a bad tag */
        ret = be->decrypt_detached(NULL, NULL, guard_page, 0U, mac,
                                   adp, adlen, nonce, key);
        check_true(ret == -1, be->name,
                   "verification-only empty ciphertext with bad tag not rejected");
    }
    (void) c_base;
}

/*
 * A failed authentication must not leave data behind that a caller
 * could mistake for verified plaintext: the return value must be -1,
 * the reported length 0, the output buffer must be wiped (backend
 * specific fill byte) and differ from the plaintext, and the sentinels
 * around the buffer must be intact. A valid decryption into the same
 * buffer must still succeed afterwards.
 */
static void
test_failed_authentication(const aead_backend *be, unsigned char *c_base,
                           unsigned char *m_base)
{
    static const size_t mlens[]  = { 0U, 1U, 15U, 16U, 17U, 64U, 1000U, MAX_MLEN };
    static const size_t adlens[] = { 0U, 32U };
    unsigned char      *c = c_base + CANARY_LEN;
    unsigned char      *m = m_base + CANARY_LEN;
    unsigned char       mac[MAX_ABYTES];
    unsigned long long  found_clen;
    unsigned long long  found_maclen;
    unsigned long long  mlen_out;
    size_t              mlen;
    size_t              adlen;
    size_t              mi;
    size_t              ai;
    size_t              clen;
    int                 ret;

    for (mi = 0U; mi < sizeof mlens / sizeof mlens[0]; mi++) {
        mlen = mlens[mi];
        clen = mlen + be->abytes;
        for (ai = 0U; ai < sizeof adlens / sizeof adlens[0]; ai++) {
            const unsigned char *adp;

            adlen = adlens[ai];
            adp   = adlen > 0U ? ad : NULL;

            /* --- combined API, corrupted tag --- */
            slab_arm(c_base, MAX_MLEN + MAX_ABYTES);
            be->encrypt(c, &found_clen, msg, mlen, adp, adlen,
                        NULL, nonce, key);
            check_true(found_clen == clen, be->name, "encrypt: wrong clen");
            c[clen - 1U] ^= 0x80;
            slab_arm(m_base, MAX_MLEN);
            memset(m, BODY_BYTE, MAX_MLEN);
            mlen_out = 0xdeadbeefULL;
            ret = be->decrypt(m, &mlen_out, NULL, c, clen,
                              adp, adlen, nonce, key);
            check_true(ret == -1, be->name, "bad tag was not rejected");
            check_true(mlen_out == 0U, be->name,
                       "bad tag: mlen not reset to 0");
            check_true(slab_intact(m_base, MAX_MLEN), be->name,
                       "bad tag: output buffer canaries damaged");
            if (mlen > 0U) {
                check_true(buffer_is_filled_with(m, mlen, be->failure_fill),
                           be->name,
                           "bad tag: output buffer not wiped");
                check_true(memcmp(m, msg, mlen) != 0, be->name,
                           "bad tag: output buffer holds the plaintext");
            }

            /* --- combined API, corrupted ciphertext body --- */
            if (mlen > 0U) {
                be->encrypt(c, &found_clen, msg, mlen, adp, adlen,
                            NULL, nonce, key);
                c[0] ^= 0x40;
                slab_arm(m_base, MAX_MLEN);
                memset(m, BODY_BYTE, MAX_MLEN);
                mlen_out = 0xdeadbeefULL;
                ret = be->decrypt(m, &mlen_out, NULL, c, clen,
                                  adp, adlen, nonce, key);
                check_true(ret == -1, be->name,
                           "corrupted ciphertext was not rejected");
                check_true(mlen_out == 0U, be->name,
                           "corrupted ciphertext: mlen not reset to 0");
                check_true(slab_intact(m_base, MAX_MLEN), be->name,
                           "corrupted ciphertext: canaries damaged");
                check_true(buffer_is_filled_with(m, mlen, be->failure_fill),
                           be->name,
                           "corrupted ciphertext: output buffer not wiped");
                check_true(memcmp(m, msg, mlen) != 0, be->name,
                           "corrupted ciphertext: output holds the plaintext");
            }

            /* --- combined API, tampered additional data --- */
            be->encrypt(c, &found_clen, msg, mlen, adp, adlen,
                        NULL, nonce, key);
            slab_arm(m_base, MAX_MLEN);
            memset(m, BODY_BYTE, MAX_MLEN);
            mlen_out = 0xdeadbeefULL;
            if (adlen > 0U) {
                unsigned char ad_copy[MAX_ADLEN];

                memcpy(ad_copy, ad, adlen);
                ad_copy[adlen - 1U] ^= 0x01;
                ret = be->decrypt(m, &mlen_out, NULL, c, clen,
                                  ad_copy, adlen, nonce, key);
            } else {
                ret = be->decrypt(m, &mlen_out, NULL, c, clen,
                                  ad, 1U, nonce, key);
            }
            check_true(ret == -1, be->name,
                       "tampered additional data was not rejected");
            check_true(mlen_out == 0U, be->name,
                       "tampered ad: mlen not reset to 0");
            check_true(slab_intact(m_base, MAX_MLEN), be->name,
                       "tampered ad: canaries damaged");

            /* --- detached API, corrupted tag --- */
            slab_arm(c_base, MAX_MLEN + MAX_ABYTES);
            be->encrypt_detached(c, mac, &found_maclen, msg, mlen,
                                 adp, adlen, NULL, nonce, key);
            check_true(found_maclen == be->abytes, be->name,
                       "encrypt_detached: wrong maclen");
            mac[be->abytes - 1U] ^= 0x01;
            slab_arm(m_base, MAX_MLEN);
            memset(m, BODY_BYTE, MAX_MLEN);
            ret = be->decrypt_detached(m, NULL, c, mlen, mac,
                                       adp, adlen, nonce, key);
            check_true(ret == -1, be->name,
                       "detached bad tag was not rejected");
            check_true(slab_intact(m_base, MAX_MLEN), be->name,
                       "detached bad tag: canaries damaged");
            if (mlen > 0U) {
                check_true(buffer_is_filled_with(m, mlen, be->failure_fill),
                           be->name,
                           "detached bad tag: output buffer not wiped");
                check_true(memcmp(m, msg, mlen) != 0, be->name,
                           "detached bad tag: output holds the plaintext");
            }

            /* --- in-place decryption of a forged message --- */
            slab_arm(c_base, MAX_MLEN + MAX_ABYTES);
            memcpy(c, msg, mlen);
            be->encrypt(c, &found_clen, c, mlen, adp, adlen,
                        NULL, nonce, key);
            c[clen - 1U] ^= 0x80;
            mlen_out = 0xdeadbeefULL;
            ret = be->decrypt(c, &mlen_out, NULL, c, clen,
                              adp, adlen, nonce, key);
            check_true(ret == -1, be->name,
                       "in-place forged message was not rejected");
            check_true(mlen_out == 0U, be->name,
                       "in-place forged message: mlen not reset to 0");
            check_true(slab_intact(c_base, MAX_MLEN + MAX_ABYTES),
                       be->name,
                       "in-place forged message: canaries damaged");
            if (mlen > 0U) {
                check_true(buffer_is_filled_with(c, mlen, be->failure_fill),
                           be->name,
                           "in-place forged message: buffer not wiped");
                check_true(memcmp(c, msg, mlen) != 0, be->name,
                           "in-place forged message: buffer holds plaintext");
            }

            /* --- a valid message must still decrypt after failures --- */
            slab_arm(c_base, MAX_MLEN + MAX_ABYTES);
            be->encrypt(c, &found_clen, msg, mlen, adp, adlen,
                        NULL, nonce, key);
            slab_arm(m_base, MAX_MLEN);
            memset(m, BODY_BYTE, MAX_MLEN);
            mlen_out = 0U;
            ret = be->decrypt(m, &mlen_out, NULL, c, clen,
                              adp, adlen, nonce, key);
            check_true(ret == 0, be->name,
                       "valid decryption failed after previous failures");
            check_true(mlen_out == mlen, be->name,
                       "post-failure decryption: wrong mlen");
            check_true(memcmp(m, msg, mlen) == 0, be->name,
                       "post-failure decryption: wrong plaintext");
            check_true(slab_intact(m_base, MAX_MLEN), be->name,
                       "post-failure decryption: canaries damaged");
        }
    }
}

/*
 * Boundary buffer layouts: messages and AD of various sizes, including
 * empty inputs and sizes crossing 16/64-byte block and 4 KiB page
 * boundaries. The combined and detached APIs of a backend must produce
 * consistent ciphertexts, tags, plaintext and lengths, and in-place
 * operation must match separate-buffer operation.
 */
static void
test_roundtrip_consistency(const aead_backend *be, unsigned char *c_base,
                           unsigned char *d_base, unsigned char *m_base)
{
    static const size_t mlens[]  = { 0U, 1U, 15U, 16U, 17U, 63U, 64U, 65U,
                                     255U, 256U, 1024U, 4095U };
    static const size_t adlens[] = { 0U, 1U, 13U, 16U, 17U, 64U, 255U };
    unsigned char      *c  = c_base + CANARY_LEN;
    unsigned char      *dc = d_base + CANARY_LEN;
    unsigned char      *m  = m_base + CANARY_LEN;
    unsigned char       mac[MAX_ABYTES];
    unsigned long long  found_clen;
    unsigned long long  found_maclen;
    unsigned long long  mlen_out;
    size_t              mlen;
    size_t              adlen;
    size_t              mi;
    size_t              ai;
    size_t              clen;
    int                 ret;

    for (mi = 0U; mi < sizeof mlens / sizeof mlens[0]; mi++) {
        mlen = mlens[mi];
        clen = mlen + be->abytes;
        for (ai = 0U; ai < sizeof adlens / sizeof adlens[0]; ai++) {
            const unsigned char *adp;

            adlen = adlens[ai];
            adp   = adlen > 0U ? ad : NULL;

            slab_arm(c_base, MAX_MLEN + MAX_ABYTES);
            be->encrypt(c, &found_clen, msg, mlen, adp, adlen,
                        NULL, nonce, key);
            check_true(found_clen == clen, be->name,
                       "roundtrip: wrong combined clen");
            check_true(slab_intact(c_base, MAX_MLEN + MAX_ABYTES),
                       be->name, "roundtrip: encrypt overflowed");

            slab_arm(d_base, MAX_MLEN + MAX_ABYTES);
            be->encrypt_detached(dc, mac, &found_maclen, msg, mlen,
                                 adp, adlen, NULL, nonce, key);
            check_true(found_maclen == be->abytes, be->name,
                       "roundtrip: wrong maclen");
            check_true(slab_intact(d_base, MAX_MLEN + MAX_ABYTES),
                       be->name, "roundtrip: encrypt_detached overflowed");
            check_true(memcmp(dc, c, mlen) == 0, be->name,
                       "roundtrip: detached ciphertext != combined");
            check_true(memcmp(mac, c + mlen, be->abytes) == 0, be->name,
                       "roundtrip: detached tag != combined tag");

            /* combined decrypt */
            slab_arm(m_base, MAX_MLEN);
            memset(m, BODY_BYTE, MAX_MLEN);
            mlen_out = 0U;
            ret = be->decrypt(m, &mlen_out, NULL, c, clen,
                              adp, adlen, nonce, key);
            check_true(ret == 0, be->name, "roundtrip: decrypt failed");
            check_true(mlen_out == mlen, be->name,
                       "roundtrip: wrong decrypted length");
            check_true(memcmp(m, msg, mlen) == 0, be->name,
                       "roundtrip: wrong plaintext");
            check_true(slab_intact(m_base, MAX_MLEN), be->name,
                       "roundtrip: decrypt overflowed");

            /* detached decrypt of the detached ciphertext */
            memset(m, BODY_BYTE, MAX_MLEN);
            ret = be->decrypt_detached(m, NULL, dc, mlen, mac,
                                       adp, adlen, nonce, key);
            check_true(ret == 0, be->name,
                       "roundtrip: decrypt_detached failed");
            check_true(memcmp(m, msg, mlen) == 0, be->name,
                       "roundtrip: wrong detached plaintext");

            /* detached decrypt of the combined ciphertext (split) */
            memset(m, BODY_BYTE, MAX_MLEN);
            ret = be->decrypt_detached(m, NULL, c, mlen, c + mlen,
                                       adp, adlen, nonce, key);
            check_true(ret == 0, be->name,
                       "roundtrip: split combined decrypt failed");
            check_true(memcmp(m, msg, mlen) == 0, be->name,
                       "roundtrip: split combined plaintext mismatch");

            /* combined decrypt of the detached ciphertext (joined) */
            slab_arm(d_base, MAX_MLEN + MAX_ABYTES);
            memcpy(dc + mlen, mac, be->abytes);
            memset(m, BODY_BYTE, MAX_MLEN);
            mlen_out = 0U;
            ret = be->decrypt(m, &mlen_out, NULL, dc, clen,
                              adp, adlen, nonce, key);
            check_true(ret == 0, be->name,
                       "roundtrip: joined detached decrypt failed");
            check_true(mlen_out == mlen, be->name,
                       "roundtrip: joined detached length mismatch");
            check_true(memcmp(m, msg, mlen) == 0, be->name,
                       "roundtrip: joined detached plaintext mismatch");
            check_true(slab_intact(d_base, MAX_MLEN + MAX_ABYTES),
                       be->name, "roundtrip: joined decrypt overflowed");

            /* verification-only calls (m == NULL) */
            mlen_out = 0U;
            ret = be->decrypt(NULL, &mlen_out, NULL, c, clen,
                              adp, adlen, nonce, key);
            check_true(ret == 0, be->name,
                       "roundtrip: verification-only decrypt failed");
            check_true(mlen_out == mlen, be->name,
                       "roundtrip: verification-only length mismatch");
            ret = be->decrypt_detached(NULL, NULL, dc, mlen, mac,
                                       adp, adlen, nonce, key);
            check_true(ret == 0, be->name,
                       "roundtrip: verification-only detached failed");

            /* in-place combined encrypt + decrypt */
            slab_arm(c_base, MAX_MLEN + MAX_ABYTES);
            memcpy(c, msg, mlen);
            be->encrypt(c, &found_clen, c, mlen, adp, adlen,
                        NULL, nonce, key);
            check_true(found_clen == clen, be->name,
                       "in-place: wrong clen");
            mlen_out = 0U;
            ret = be->decrypt(c, &mlen_out, NULL, c, clen,
                              adp, adlen, nonce, key);
            check_true(ret == 0, be->name, "in-place: decrypt failed");
            check_true(mlen_out == mlen, be->name,
                       "in-place: wrong length");
            check_true(memcmp(c, msg, mlen) == 0, be->name,
                       "in-place: wrong plaintext");
            check_true(slab_intact(c_base, MAX_MLEN + MAX_ABYTES),
                       be->name, "in-place: canaries damaged");

            /* in-place detached encrypt + decrypt */
            slab_arm(d_base, MAX_MLEN + MAX_ABYTES);
            memcpy(dc, msg, mlen);
            be->encrypt_detached(dc, mac, &found_maclen, dc, mlen,
                                 adp, adlen, NULL, nonce, key);
            ret = be->decrypt_detached(dc, NULL, dc, mlen, mac,
                                       adp, adlen, nonce, key);
            check_true(ret == 0, be->name,
                       "in-place detached: decrypt failed");
            check_true(memcmp(dc, msg, mlen) == 0, be->name,
                       "in-place detached: wrong plaintext");
            check_true(slab_intact(d_base, MAX_MLEN + MAX_ABYTES),
                       be->name, "in-place detached: canaries damaged");
        }
    }
}

int
main(void)
{
    unsigned char *c_base;
    unsigned char *d_base;
    unsigned char *m_base;
    size_t         i;

    c_base = (unsigned char *) sodium_malloc(CANARY_LEN + MAX_MLEN +
                                             MAX_ABYTES + CANARY_LEN);
    d_base = (unsigned char *) sodium_malloc(CANARY_LEN + MAX_MLEN +
                                             MAX_ABYTES + CANARY_LEN);
    m_base = (unsigned char *) sodium_malloc(CANARY_LEN + MAX_MLEN +
                                             CANARY_LEN);

    /* identical, deterministic inputs for every backend */
    fill_pattern(key, sizeof key, 0x01U);
    fill_pattern(nonce, sizeof nonce, 0x42U);
    fill_pattern(ad, sizeof ad, 0x77U);
    fill_pattern(msg, sizeof msg, 0xa0U);

    for (i = 0U; i < sizeof backends / sizeof backends[0]; i++) {
#ifdef crypto_aead_aes256gcm_KEYBYTES
        if (strcmp(backends[i].name, "aes256gcm") == 0 &&
            crypto_aead_aes256gcm_is_available() == 0) {
            continue;
        }
#endif
        assert(backends[i].keybytes <= MAX_KEYBYTES);
        assert(backends[i].npubbytes <= MAX_NPUBBYTES);
        assert(backends[i].abytes <= MAX_ABYTES);
        test_short_ciphertext(&backends[i], c_base, m_base);
        test_failed_authentication(&backends[i], c_base, m_base);
        test_roundtrip_consistency(&backends[i], c_base, d_base, m_base);
    }

    sodium_free(c_base);
    sodium_free(d_base);
    sodium_free(m_base);

    return failures != 0;
}
