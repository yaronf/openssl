/*
 * PQC Continuity extension (draft-sheffer-tls-pqc-continuity)
 * Experimental POC implementation.
 *
 * Extension wire format (Certificate message, first CertificateEntry only):
 *   uint16 signature_algorithm
 *   uint32 algorithm_validity_period  (seconds; 0 = do not cache / clear cache)
 *
 * ClientHello and CertificateRequest carry an empty extension (presence only).
 *
 * Algorithm list: read from [pqc_continuity] Algorithms in $OPENSSL_CONF.
 * Default (if section absent): extension is disabled (opt-in via config).
 * Names must match EVP_PKEY_get0_type_name() and SSL_set1_sigalgs_list().
 *
 * Cache file format: PEM blocks, type "PQC CERT AVAILABLE CACHE".
 * Each block: DER SEQUENCE { host IA5String, port INTEGER,
 *                            sigalg INTEGER, expiry INTEGER }
 * Compatible with tests/lib/cache.py (pyasn1).
 *
 * Cache path: $PQC_CONTINUITY_CACHE, else platform default:
 *   macOS:  ~/Library/Application Support/openssl/pqc_continuity_cache.pem
 *   other:  $XDG_CONFIG_HOME/openssl/pqc_continuity_cache.pem
 */

#include "ssl_local.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
# include <windows.h>
# include <shlobj.h>
#else
# include <sys/stat.h>
# include <unistd.h>
#endif

#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

/* Default algorithm_validity_period advertised by the server (seconds). */
#define PQC_DEFAULT_VALIDITY_PERIOD  (365 * 24 * 3600)  /* 1 year */

/* PEM block type for cache entries. */
#define PQC_PEM_TYPE  "PQC CERT AVAILABLE CACHE"

/* Extension wire size: 2 bytes sigalg + 4 bytes validity_period. */
#define PQC_EXT_DATA_LEN  6

/* Maximum number of algorithms in [pqc_continuity] Algorithms. */
#define PQC_MAX_ALGS  32

/* -------------------------------------------------------------------------
 * Types
 * ---------------------------------------------------------------------- */

/* Algorithm table entry: name → TLS SignatureScheme value. */
typedef struct {
    char     name[64];   /* OpenSSL sigalg name, e.g. "mldsa44" */
    uint16_t scheme;     /* TLS SignatureScheme value */
} pqc_alg_t;

/* Per-context state, passed via add_arg / parse_arg. */
typedef struct {
    int         enabled;
    uint32_t    validity_period;
    pqc_alg_t   algs[PQC_MAX_ALGS];
    int         nalgs;
    char        sigalgs_list[256];  /* colon-separated, for SSL_set1_sigalgs_list */
    int         server_sent_cr;
} pqc_ctx_t;

/* -------------------------------------------------------------------------
 * Algorithm helpers
 * ---------------------------------------------------------------------- */

/* Static name → TLS SignatureScheme table, from TLSEXT_SIGALG_* in ssl_local.h. */
typedef struct { const char *name; uint16_t scheme; } pqc_scheme_entry_t;

static const pqc_scheme_entry_t pqc_scheme_table[] = {
    { "mldsa44",    TLSEXT_SIGALG_mldsa44 },
    { "mldsa65",    TLSEXT_SIGALG_mldsa65 },
    { "mldsa87",    TLSEXT_SIGALG_mldsa87 },
    { NULL, 0 }
};

static uint16_t pqc_resolve_scheme(const char *name)
{
    const pqc_scheme_entry_t *e;
    for (e = pqc_scheme_table; e->name != NULL; e++)
        if (strcasecmp(name, e->name) == 0)
            return e->scheme;
    return 0;
}

static const pqc_alg_t *pqc_alg_by_scheme(const pqc_ctx_t *pctx, uint16_t scheme)
{
    int i;
    for (i = 0; i < pctx->nalgs; i++)
        if (pctx->algs[i].scheme == scheme)
            return &pctx->algs[i];
    return NULL;
}

static uint16_t pqc_pkey_to_scheme(const pqc_ctx_t *pctx, EVP_PKEY *pkey)
{
    const char *alg_name;
    int i;

    if (pkey == NULL || pctx->nalgs == 0)
        return 0;
    alg_name = EVP_PKEY_get0_type_name(pkey);
    if (alg_name == NULL)
        return 0;
    for (i = 0; i < pctx->nalgs; i++)
        if (strcasecmp(alg_name, pctx->algs[i].name) == 0)
            return pctx->algs[i].scheme;
    return 0;
}

/*
 * Parse a comma-separated algorithm list into pctx->algs[] and
 * build pctx->sigalgs_list (colon-separated, for SSL_set1_sigalgs_list).
 */
static void pqc_parse_alg_list(pqc_ctx_t *pctx, const char *alg_str)
{
    char buf[512];
    char *p, *tok, *save = NULL;
    char list_buf[256];
    int list_len = 0;

    pctx->nalgs = 0;
    pctx->sigalgs_list[0] = '\0';

    snprintf(buf, sizeof(buf), "%s", alg_str);

    for (p = buf; ; p = NULL) {
#ifdef _WIN32
        tok = strtok_s(p, ",", &save);
#else
        tok = strtok_r(p, ",", &save);
#endif
        if (tok == NULL) break;

        /* Trim whitespace */
        while (*tok == ' ' || *tok == '\t') tok++;
        {
            char *end = tok + strlen(tok) - 1;
            while (end > tok && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
                *end-- = '\0';
        }
        if (*tok == '\0') continue;
        if (pctx->nalgs >= PQC_MAX_ALGS) break;

        {
            uint16_t scheme = pqc_resolve_scheme(tok);
            if (scheme == 0) {
                fprintf(stderr, "pqc_continuity: unknown algorithm '%s', skipping\n", tok);
                continue;
            }
            snprintf(pctx->algs[pctx->nalgs].name,
                     sizeof(pctx->algs[pctx->nalgs].name), "%s", tok);
            pctx->algs[pctx->nalgs].scheme = scheme;
            pctx->nalgs++;

            if (list_len > 0 && list_len < (int)sizeof(list_buf) - 1)
                list_buf[list_len++] = ':';
            {
                int rem = (int)sizeof(list_buf) - list_len - 1;
                int n = snprintf(list_buf + list_len, rem, "%s", tok);
                if (n > 0 && n < rem)
                    list_len += n;
            }
        }
    }

    list_buf[list_len] = '\0';
    snprintf(pctx->sigalgs_list, sizeof(pctx->sigalgs_list), "%s", list_buf);
}

/* -------------------------------------------------------------------------
 * Cache path / directory helpers
 * ---------------------------------------------------------------------- */

static void pqc_cache_path(char *buf, size_t buflen)
{
    const char *env = getenv("PQC_CONTINUITY_CACHE");
    if (env != NULL) {
        snprintf(buf, buflen, "%s", env);
        return;
    }

#ifdef __APPLE__
    {
        const char *home = getenv("HOME");
        if (home == NULL) home = ".";
        snprintf(buf, buflen,
                 "%s/Library/Application Support/openssl/pqc_continuity_cache.pem",
                 home);
    }
#elif defined(_WIN32)
    {
        char appdata[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata)))
            snprintf(buf, buflen, "%s\\openssl\\pqc_continuity_cache.pem", appdata);
        else
            snprintf(buf, buflen, "pqc_continuity_cache.pem");
    }
#else
    {
        const char *xdg = getenv("XDG_CONFIG_HOME");
        if (xdg != NULL)
            snprintf(buf, buflen, "%s/openssl/pqc_continuity_cache.pem", xdg);
        else {
            const char *home = getenv("HOME");
            if (home == NULL) home = ".";
            snprintf(buf, buflen, "%s/.config/openssl/pqc_continuity_cache.pem", home);
        }
    }
#endif
}

static void pqc_makedirs(const char *path)
{
    char tmp[512];
    char *p;

    snprintf(tmp, sizeof(tmp), "%s", path);
    p = strrchr(tmp, '/');
#ifdef _WIN32
    if (p == NULL) p = strrchr(tmp, '\\');
#endif
    if (p == NULL) return;
    *p = '\0';
    if (tmp[0] == '\0') return;

#ifdef _WIN32
    for (p = tmp + 1; *p; p++) {
        if (*p == '\\' || *p == '/') {
            char c = *p; *p = '\0';
            CreateDirectoryA(tmp, NULL);
            *p = c;
        }
    }
    CreateDirectoryA(tmp, NULL);
#else
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }
    mkdir(tmp, 0700);
#endif
}

/* -------------------------------------------------------------------------
 * Per-connection host/port from SSL object
 * ---------------------------------------------------------------------- */

static void pqc_get_host_port(SSL *s, char *host, size_t hostlen, int *port)
{
    const char *sni = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    BIO *rbio = SSL_get_rbio(s);

    if (sni != NULL && sni[0] != '\0') {
        snprintf(host, hostlen, "%s", sni);
    } else {
        const char *h = (rbio != NULL) ? BIO_get_conn_hostname(rbio) : NULL;
        snprintf(host, hostlen, "%s", (h != NULL) ? h : "localhost");
    }

    {
        const char *port_str = (rbio != NULL) ? BIO_get_conn_port(rbio) : NULL;
        *port = (port_str != NULL && port_str[0] != '\0') ? atoi(port_str) : 443;
    }
}

/* -------------------------------------------------------------------------
 * ASN.1 DER encode / decode
 * Schema: SEQUENCE { host IA5String, port INTEGER, sigalg INTEGER, expiry INTEGER }
 * ---------------------------------------------------------------------- */

/* Push a long integer onto an ASN1_SEQUENCE_ANY. Returns 0 on failure. */
static int pqc_seq_add_integer(ASN1_SEQUENCE_ANY *seq, long val)
{
    ASN1_TYPE *t = ASN1_TYPE_new();
    if (t == NULL) return 0;
    t->type = V_ASN1_INTEGER;
    t->value.integer = ASN1_INTEGER_new();
    if (t->value.integer == NULL || !ASN1_INTEGER_set_int64(t->value.integer, val)
            || !sk_ASN1_TYPE_push(seq, t)) {
        ASN1_TYPE_free(t);
        return 0;
    }
    return 1;
}

static unsigned char *pqc_encode_entry(const char *host, int port,
                                        int sigalg, long expiry, int *out_len)
{
    ASN1_SEQUENCE_ANY *seq = sk_ASN1_TYPE_new_null();
    ASN1_TYPE *t;
    unsigned char *der = NULL;
    int len;

    if (seq == NULL) return NULL;

    /* host IA5String */
    t = ASN1_TYPE_new();
    if (t == NULL) goto err;
    t->type = V_ASN1_IA5STRING;
    t->value.ia5string = ASN1_IA5STRING_new();
    if (t->value.ia5string == NULL
            || !ASN1_STRING_set(t->value.ia5string, host, (int)strlen(host))
            || !sk_ASN1_TYPE_push(seq, t)) {
        ASN1_TYPE_free(t);
        goto err;
    }

    if (!pqc_seq_add_integer(seq, (long)port)
            || !pqc_seq_add_integer(seq, (long)sigalg)
            || !pqc_seq_add_integer(seq, expiry))
        goto err;

    len = i2d_ASN1_SEQUENCE_ANY(seq, &der);
    if (len <= 0) { der = NULL; goto err; }
    *out_len = len;

err:
    sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
    return der;
}

static int pqc_decode_entry(const unsigned char *der, int len,
                             char *host, size_t hostlen,
                             int *port, int *sigalg, long *expiry)
{
    const unsigned char *p = der;
    ASN1_SEQUENCE_ANY *seq = NULL;
    ASN1_TYPE *t;
    int ret = 0;

    seq = d2i_ASN1_SEQUENCE_ANY(NULL, &p, len);
    if (seq == NULL || sk_ASN1_TYPE_num(seq) != 4)
        goto err;

    t = sk_ASN1_TYPE_value(seq, 0);
    if (t->type != V_ASN1_IA5STRING) goto err;
    {
        int slen = t->value.ia5string->length;
        if (slen < 0 || (size_t)slen >= hostlen) goto err;
        memcpy(host, t->value.ia5string->data, slen);
        host[slen] = '\0';
    }

    t = sk_ASN1_TYPE_value(seq, 1);
    if (t->type != V_ASN1_INTEGER) goto err;
    *port = (int)ASN1_INTEGER_get(t->value.integer);

    t = sk_ASN1_TYPE_value(seq, 2);
    if (t->type != V_ASN1_INTEGER) goto err;
    *sigalg = (int)ASN1_INTEGER_get(t->value.integer);

    t = sk_ASN1_TYPE_value(seq, 3);
    if (t->type != V_ASN1_INTEGER) goto err;
    {
        int64_t v = 0;
        ASN1_INTEGER_get_int64(&v, t->value.integer);
        *expiry = (long)v;
    }

    ret = 1;
err:
    if (seq != NULL)
        sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
    return ret;
}

/* -------------------------------------------------------------------------
 * Cache read / write
 * ---------------------------------------------------------------------- */

static int pqc_cache_lookup(const char *host, int port,
                             int *sigalg, long *expiry_out)
{
    char path[512];
    BIO *bio = NULL;
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long datalen;
    int found = 0;
    time_t now = time(NULL);

    pqc_cache_path(path, sizeof(path));
    bio = BIO_new_file(path, "r");
    if (bio == NULL) { ERR_clear_error(); return 0; }

    while (PEM_read_bio(bio, &name, &header, &data, &datalen) == 1) {
        if (strcmp(name, PQC_PEM_TYPE) == 0) {
            char h[256];
            int p = 0, sa = 0;
            long exp = 0;
            if (pqc_decode_entry(data, (int)datalen, h, sizeof(h), &p, &sa, &exp)
                    && strcmp(h, host) == 0 && p == port) {
                if (exp > (long)now) {
                    *sigalg = sa;
                    *expiry_out = exp;
                    found = 1;
                }
                OPENSSL_free(name);
                OPENSSL_free(header);
                OPENSSL_free(data);
                break;
            }
        }
        OPENSSL_free(name); name = NULL;
        OPENSSL_free(header); header = NULL;
        OPENSSL_free(data); data = NULL;
    }
    ERR_clear_error();
    BIO_free(bio);
    return found;
}

/*
 * Open a temp file for writing the new cache, copy existing entries
 * (optionally excluding a given host:port), write them to wbio.
 * Returns an open BIO on the temp file, or NULL on error.
 * Caller must rename tmppath → path and free wbio.
 */
static BIO *pqc_cache_open_tmp(const char *path, char *tmppath, size_t tmplen,
                                const char *exclude_host, int exclude_port)
{
    BIO *rbio = NULL, *wbio = NULL;
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long datalen;
#ifdef _WIN32
    snprintf(tmppath, tmplen, "%s.tmp.XXXXXX", path);
    if (_mktemp_s(tmppath, tmplen) != 0) return NULL;
    wbio = BIO_new_file(tmppath, "w");
#else
    int fd;
    snprintf(tmppath, tmplen, "%s.tmp.XXXXXX", path);
    fd = mkstemp(tmppath);
    if (fd < 0) return NULL;
    wbio = BIO_new_fd(fd, BIO_CLOSE);
#endif
    if (wbio == NULL) return NULL;

    rbio = BIO_new_file(path, "r");
    if (rbio != NULL) {
        while (PEM_read_bio(rbio, &name, &header, &data, &datalen) == 1) {
            if (strcmp(name, PQC_PEM_TYPE) == 0) {
                char h[256];
                int p = 0, sa = 0;
                long exp = 0;
                int skip = exclude_host != NULL
                    && pqc_decode_entry(data, (int)datalen, h, sizeof(h), &p, &sa, &exp)
                    && strcmp(h, exclude_host) == 0 && p == exclude_port;
                if (!skip)
                    PEM_write_bio(wbio, PQC_PEM_TYPE, "", data, datalen);
            }
            OPENSSL_free(name); name = NULL;
            OPENSSL_free(header); header = NULL;
            OPENSSL_free(data); data = NULL;
        }
        ERR_clear_error();
        BIO_free(rbio);
    } else {
        ERR_clear_error();
    }
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    return wbio;
}

static int pqc_cache_update(const char *host, int port, int sigalg, long expiry)
{
    char path[512], tmppath[528];
    unsigned char *newder = NULL;
    int newlen = 0, ret = 0;
    BIO *wbio = NULL;

    pqc_cache_path(path, sizeof(path));
    pqc_makedirs(path);

    wbio = pqc_cache_open_tmp(path, tmppath, sizeof(tmppath), host, port);
    if (wbio == NULL) return 0;

    newder = pqc_encode_entry(host, port, sigalg, expiry, &newlen);
    if (newder == NULL) goto err;

    PEM_write_bio(wbio, PQC_PEM_TYPE, "", newder, newlen);
    BIO_flush(wbio);
    BIO_free(wbio); wbio = NULL;

#ifdef _WIN32
    DeleteFileA(path);
    if (!MoveFileA(tmppath, path)) goto err;
#else
    if (rename(tmppath, path) != 0) goto err;
#endif
    ret = 1;

err:
    if (wbio != NULL) { BIO_free(wbio); unlink(tmppath); }
    OPENSSL_free(newder);
    return ret;
}

static int pqc_cache_delete(const char *host, int port)
{
    char path[512], tmppath[528];
    int ret = 0;
    BIO *wbio;

    pqc_cache_path(path, sizeof(path));
    wbio = pqc_cache_open_tmp(path, tmppath, sizeof(tmppath), host, port);
    if (wbio == NULL) return 0;

    BIO_flush(wbio);
    BIO_free(wbio);

#ifdef _WIN32
    DeleteFileA(path);
    if (!MoveFileA(tmppath, path)) return 0;
#else
    if (rename(tmppath, path) != 0) return 0;
#endif
    ret = 1;
    return ret;
}

/* -------------------------------------------------------------------------
 * Extension callbacks
 * ---------------------------------------------------------------------- */

static int pqc_add_cb(SSL *s, unsigned int ext_type,
                       unsigned int context,
                       const unsigned char **out, size_t *outlen,
                       X509 *x, size_t chainidx,
                       int *al, void *add_arg)
{
    pqc_ctx_t *pctx = (pqc_ctx_t *)add_arg;

    if (pctx == NULL || !pctx->enabled)
        return 0;

    if (context & SSL_EXT_CLIENT_HELLO) {
        if (SSL_is_server(s)) return 0;

        /* On cache hit, restrict offered sigalgs to PQC-only before CH goes out. */
        {
            char host[256];
            int port = 0, cached_sigalg = 0;
            long cached_expiry = 0;

            pqc_get_host_port(s, host, sizeof(host), &port);
            if (pqc_cache_lookup(host, port, &cached_sigalg, &cached_expiry)
                    && pqc_alg_by_scheme(pctx, (uint16_t)cached_sigalg) != NULL
                    && pctx->sigalgs_list[0] != '\0') {
                if (!SSL_set1_sigalgs_list(s, pctx->sigalgs_list))
                    ERR_clear_error(); /* non-fatal */
            }
        }

        *out = NULL; *outlen = 0;
        return 1;
    }

    if (context & SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        if (!SSL_is_server(s)) return 0;
        *out = NULL; *outlen = 0;
        return 1;
    }

    if (context & SSL_EXT_TLS1_3_CERTIFICATE) {
        EVP_PKEY *pkey;
        uint16_t scheme;
        unsigned char *buf;

        if (chainidx != 0) return 0;

        pkey = (x != NULL) ? X509_get0_pubkey(x) : NULL;
        scheme = pqc_pkey_to_scheme(pctx, pkey);
        if (scheme == 0) {
            /* Traditional cert: send empty extension as presence signal. */
            *out = NULL; *outlen = 0;
            return 1;
        }

        buf = OPENSSL_malloc(PQC_EXT_DATA_LEN);
        if (buf == NULL) { *al = SSL_AD_INTERNAL_ERROR; return -1; }
        buf[0] = (scheme >> 8) & 0xff;
        buf[1] =  scheme       & 0xff;
        buf[2] = (pctx->validity_period >> 24) & 0xff;
        buf[3] = (pctx->validity_period >> 16) & 0xff;
        buf[4] = (pctx->validity_period >>  8) & 0xff;
        buf[5] =  pctx->validity_period        & 0xff;
        *out = buf; *outlen = PQC_EXT_DATA_LEN;
        return 1;
    }

    return 0;
}

static void pqc_free_cb(SSL *s, unsigned int ext_type,
                         unsigned int context,
                         const unsigned char *out, void *add_arg)
{
    if (context & SSL_EXT_TLS1_3_CERTIFICATE)
        OPENSSL_free((void *)out);
}

static int pqc_parse_cb(SSL *s, unsigned int ext_type,
                          unsigned int context,
                          const unsigned char *in, size_t inlen,
                          X509 *x, size_t chainidx,
                          int *al, void *parse_arg)
{
    pqc_ctx_t *pctx = (pqc_ctx_t *)parse_arg;

    if (pctx == NULL || !pctx->enabled)
        return 1;

    if (context & SSL_EXT_CLIENT_HELLO)
        return 1; /* server notes client support; no payload */

    if (context & SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        if (!SSL_is_server(s))
            pctx->server_sent_cr = 1;
        return 1;
    }

    if (context & SSL_EXT_TLS1_3_CERTIFICATE) {
        uint16_t scheme;
        uint32_t validity;
        char host[256];
        int port = 0;

        if (chainidx != 0) return 1;
        if (inlen == 0)    return 1; /* empty: no cache update */
        if (inlen != PQC_EXT_DATA_LEN) { *al = SSL_AD_DECODE_ERROR; return 0; }

        scheme   = ((uint16_t)in[0] << 8) | (uint16_t)in[1];
        validity = ((uint32_t)in[2] << 24) | ((uint32_t)in[3] << 16)
                 | ((uint32_t)in[4] <<  8) |  (uint32_t)in[5];

        if (pqc_alg_by_scheme(pctx, scheme) == NULL)
            return 1; /* not in configured list: ignore per §3.3 */

        pqc_get_host_port(s, host, sizeof(host), &port);

        if (validity == 0)
            pqc_cache_delete(host, port);
        else
            pqc_cache_update(host, port, (int)scheme,
                             (long)time(NULL) + (long)validity);
    }

    return 1;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

int pqc_cont_init(SSL_CTX *ctx)
{
    pqc_ctx_t *pctx;
    const char *alg_str = NULL;
    char alg_buf[512];
    int section_found = 0;
    unsigned int contexts;

    pctx = OPENSSL_zalloc(sizeof(*pctx));
    if (pctx == NULL) return 0;

    pctx->enabled = 1;
    pctx->validity_period = PQC_DEFAULT_VALIDITY_PERIOD;

    /* Read [pqc_continuity] from $OPENSSL_CONF; no-op if section absent. */
    {
        CONF *conf = NULL;
        long eline = 0;
        const char *conffile = getenv("OPENSSL_CONF");
        if (conffile == NULL) conffile = getenv("SSLEAY_CONF");
        if (conffile != NULL) {
            conf = NCONF_new(NULL);
            if (conf != NULL && NCONF_load(conf, conffile, &eline) > 0) {
                char *val;

                val = NCONF_get_string(conf, "pqc_continuity", "Enable");
                if (val != NULL) {
                    section_found = 1;
                    if (strcasecmp(val, "no") == 0)
                        pctx->enabled = 0;
                } else {
                    ERR_clear_error();
                }

                val = NCONF_get_string(conf, "pqc_continuity", "Algorithms");
                if (val != NULL) {
                    section_found = 1;
                    snprintf(alg_buf, sizeof(alg_buf), "%s", val);
                    alg_str = alg_buf;
                } else {
                    ERR_clear_error();
                }
            }
            NCONF_free(conf);
            ERR_clear_error();
        }
    }

    if (!section_found) {
        OPENSSL_free(pctx);
        return 1; /* no config section: silently disabled */
    }

    if (alg_str != NULL)
        pqc_parse_alg_list(pctx, alg_str);

    if (pctx->nalgs == 0 && pctx->enabled) {
        fprintf(stderr, "pqc_continuity: no valid PQC algorithms configured, "
                        "extension disabled\n");
        pctx->enabled = 0;
    }

    contexts = SSL_EXT_CLIENT_HELLO
             | SSL_EXT_TLS1_3_CERTIFICATE_REQUEST
             | SSL_EXT_TLS1_3_CERTIFICATE;

    if (!SSL_CTX_add_custom_ext(ctx, TLSEXT_TYPE_pq_cert_available, contexts,
                                 pqc_add_cb, pqc_free_cb, pctx,
                                 pqc_parse_cb, pctx)) {
        OPENSSL_free(pctx);
        return 0;
    }

    return 1;
}
