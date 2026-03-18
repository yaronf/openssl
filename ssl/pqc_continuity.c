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
 * PQC algorithm registry: static table of known NIST PQC sigalgs, extensible
 * at runtime via pqc_cont_register_sigalg() (e.g., from a provider).
 *
 * Cache file format: PEM blocks, type "PQC CERT AVAILABLE CACHE".
 * Each block: DER SEQUENCE { host IA5String, port INTEGER, expiry INTEGER }
 * Compatible with tests/lib/cache.py (pyasn1).
 *
 * Cache path: read from [pqc_continuity] CachePath in $OPENSSL_CONF.
 * If absent, caching is disabled (no writes or reads).
 */

#include "ssl_local.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#ifndef _WIN32
# include <sys/socket.h>
# include <netinet/in.h>
#else
# include <winsock2.h>
# include <ws2tcpip.h>
#endif


#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>

/* -------------------------------------------------------------------------
 * Constants
 * ---------------------------------------------------------------------- */

/* PEM block type for cache entries. */
#define PQC_PEM_TYPE  "PQC CERT AVAILABLE CACHE"

/* Extension wire size: 2 bytes sigalg + 4 bytes validity_period. */
#define PQC_EXT_DATA_LEN  6

/* Initial allocation for in-memory cache entries. */
#define PQC_CACHE_INIT  4

/* -------------------------------------------------------------------------
 * Types
 * ---------------------------------------------------------------------- */

/* Algorithm registry entry: IANA TLS SignatureScheme value. */
typedef struct {
    uint16_t scheme;
} pqc_alg_t;

/* In-memory cache entry. */
typedef struct {
    char host[256];
    int  port;
    time_t expiry;       /* Unix timestamp */
} pqc_entry_t;

/* Per-context state, passed via add_arg / parse_arg. */
typedef struct {
    uint32_t     validity_period;
    char         cache_path[512];
    int          cache_enabled; /* 1 if CachePath was set; 0 = no persistence */
    int          server_sent_cr;
    pqc_entry_t *cache;     /* heap-allocated, grown with OPENSSL_realloc */
    int          ncache;
    int          cache_cap;
} pqc_ctx_t;

/* -------------------------------------------------------------------------
 * Global PQC algorithm registry
 *
 * Static table of all known NIST PQC sigalgs with IANA-assigned TLS
 * SignatureScheme values.  Algorithms not yet supported by the current
 * OpenSSL build are silently skipped (pqc_pkey_to_scheme returns 0 for them)
 * and activate automatically once the build adds support.
 *
 * The bar to add an algorithm here is intentionally low: the TLS stack
 * enforces all normal signature policy (negotiated sigalgs, cert chain
 * validation).  This table is only a filter for the pq_cert_available
 * extension — it does not grant any additional trust.
 *
 * Extend at runtime with pqc_cont_register_sigalg() (e.g., from a provider).
 * ---------------------------------------------------------------------- */

/* ML-DSA (FIPS 204), IANA values 0x0904–0x0906 */
#define PQC_MLDSA44   0x0904
#define PQC_MLDSA65   0x0905
#define PQC_MLDSA87   0x0906

/* SLH-DSA (FIPS 205), IANA values 0x0911–0x091C */
#define PQC_SLHDSA_SHA2_128S  0x0911
#define PQC_SLHDSA_SHA2_128F  0x0912
#define PQC_SLHDSA_SHA2_192S  0x0913
#define PQC_SLHDSA_SHA2_192F  0x0914
#define PQC_SLHDSA_SHA2_256S  0x0915
#define PQC_SLHDSA_SHA2_256F  0x0916
#define PQC_SLHDSA_SHAKE_128S 0x0917
#define PQC_SLHDSA_SHAKE_128F 0x0918
#define PQC_SLHDSA_SHAKE_192S 0x0919
#define PQC_SLHDSA_SHAKE_192F 0x091A
#define PQC_SLHDSA_SHAKE_256S 0x091B
#define PQC_SLHDSA_SHAKE_256F 0x091C

static pqc_alg_t pqc_alg_registry[] = {
    /* ML-DSA (FIPS 204) */
    { PQC_MLDSA44          },
    { PQC_MLDSA65          },
    { PQC_MLDSA87          },
    /* SLH-DSA (FIPS 205) — not yet in this OpenSSL build; skipped at init */
    { PQC_SLHDSA_SHA2_128S },
    { PQC_SLHDSA_SHA2_128F },
    { PQC_SLHDSA_SHA2_192S },
    { PQC_SLHDSA_SHA2_192F },
    { PQC_SLHDSA_SHA2_256S },
    { PQC_SLHDSA_SHA2_256F },
    { PQC_SLHDSA_SHAKE_128S },
    { PQC_SLHDSA_SHAKE_128F },
    { PQC_SLHDSA_SHAKE_192S },
    { PQC_SLHDSA_SHAKE_192F },
    { PQC_SLHDSA_SHAKE_256S },
    { PQC_SLHDSA_SHAKE_256F },
    { 0 }  /* sentinel */
};

/* Dynamic extensions registered via pqc_cont_register_sigalg(). */
static pqc_alg_t  *pqc_dyn_registry  = NULL;
static int         pqc_dyn_nalloc    = 0;
static int         pqc_dyn_nentries  = 0;

/*
 * Register an additional PQC sigalg at runtime (e.g., from a provider).
 * Returns 1 on success, 0 on failure.
 */
int pqc_cont_register_sigalg(uint16_t scheme)
{
    pqc_alg_t *p;
    if (scheme == 0) return 0;
    if (pqc_dyn_nentries >= pqc_dyn_nalloc) {
        int newalloc = pqc_dyn_nalloc == 0 ? 4 : pqc_dyn_nalloc * 2;
        p = OPENSSL_realloc(pqc_dyn_registry, newalloc * sizeof(pqc_alg_t));
        if (p == NULL) return 0;
        pqc_dyn_registry = p;
        pqc_dyn_nalloc = newalloc;
    }
    pqc_dyn_registry[pqc_dyn_nentries].scheme = scheme;
    pqc_dyn_nentries++;
    return 1;
}

/* Look up a scheme value in the combined (static + dynamic) registry. */
static const pqc_alg_t *pqc_alg_by_scheme(uint16_t scheme)
{
    int i;
    for (i = 0; pqc_alg_registry[i].scheme != 0; i++)
        if (pqc_alg_registry[i].scheme == scheme)
            return &pqc_alg_registry[i];
    for (i = 0; i < pqc_dyn_nentries; i++)
        if (pqc_dyn_registry[i].scheme == scheme)
            return &pqc_dyn_registry[i];
    return NULL;
}

/*
 * Map a pkey to its TLS SignatureScheme value by matching the pkey's base NID
 * against the SSL_CTX's sigalg_lookup_cache.  Name matching is unreliable
 * because EVP_PKEY_get0_type_name() returns the OID long name (e.g.
 * "ML-DSA-44") while sigalg_lookup_cache uses the TLS name (e.g. "mldsa44").
 */
static uint16_t pqc_pkey_to_scheme(SSL_CTX *ctx, EVP_PKEY *pkey)
{
    int nid = NID_undef;
    size_t i;

    if (pkey == NULL) return 0;

    /*
     * For provider-based keys (e.g. ML-DSA), EVP_PKEY_get_base_id() returns
     * NID_undef.  Use ssl_cert_lookup_by_pkey() instead, which uses
     * EVP_PKEY_is_a() against OID short/long names and handles provider keys.
     */
    {
        const SSL_CERT_LOOKUP *scl = ssl_cert_lookup_by_pkey(pkey, NULL, ctx);
        if (scl != NULL)
            nid = scl->pkey_nid;
    }
    if (nid == NID_undef) return 0;

    for (i = 0; i < ctx->sigalg_lookup_cache_len; i++) {
        const SIGALG_LOOKUP *lu = &ctx->sigalg_lookup_cache[i];
        if (lu->sig == nid && lu->sigalg != 0
                && pqc_alg_by_scheme(lu->sigalg) != NULL)
            return lu->sigalg;
    }
    return 0;
}


/* -------------------------------------------------------------------------
 * Per-connection host/port from SSL object
 * ---------------------------------------------------------------------- */

static void pqc_get_host_port(SSL *s, char *host, size_t hostlen, int *port)
{
    const char *sni = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
    BIO *rbio = SSL_get_rbio(s);

    /* Host: prefer SNI; fall back to BIO conn hostname. */
    if (sni != NULL && sni[0] != '\0') {
        snprintf(host, hostlen, "%s", sni);
    } else {
        const char *h = NULL;
        BIO *b;
        for (b = rbio; b != NULL; b = BIO_next(b)) {
            h = BIO_get_conn_hostname(b);
            if (h != NULL && h[0] != '\0')
                break;
        }
        snprintf(host, hostlen, "%s", (h != NULL && h[0] != '\0') ? h : "localhost");
    }

    /*
     * Port: use getpeername() on the underlying socket fd.
     *
     * BIO_get_conn_port() only works on BIO_s_connect BIOs.  The s_client app
     * creates a raw socket and wraps it with BIO_new_socket(), so the BIO chain
     * type is "socket" and BIO_get_conn_port() returns NULL.  Walking the chain
     * doesn't help — there is no connect BIO anywhere.  getpeername() on the
     * socket fd is the reliable cross-platform way to get the remote port.
     */
    *port = 443; /* default */
    {
        int fd = -1;
        BIO *b;
        for (b = rbio; b != NULL; b = BIO_next(b)) {
            if (BIO_get_fd(b, &fd) > 0 && fd >= 0)
                break;
            fd = -1;
        }
        if (fd >= 0) {
            union {
                struct sockaddr sa;
                struct sockaddr_in sin;
                struct sockaddr_in6 sin6;
            } addr;
            socklen_t addrlen = sizeof(addr);
            if (getpeername(fd, &addr.sa, &addrlen) == 0) {
                if (addr.sa.sa_family == AF_INET)
                    *port = ntohs(addr.sin.sin_port);
                else if (addr.sa.sa_family == AF_INET6)
                    *port = ntohs(addr.sin6.sin6_port);
            }
        }
    }
}

/* -------------------------------------------------------------------------
 * ASN.1 DER encode / decode
 * Schema: SEQUENCE { host IA5String, port INTEGER, expiry INTEGER }
 * ---------------------------------------------------------------------- */

typedef struct {
    ASN1_IA5STRING *host;
    ASN1_INTEGER   *port;
    ASN1_INTEGER   *expiry;
} PQC_CACHE_ENTRY;

ASN1_SEQUENCE(PQC_CACHE_ENTRY) = {
    ASN1_SIMPLE(PQC_CACHE_ENTRY, host,   ASN1_IA5STRING),
    ASN1_SIMPLE(PQC_CACHE_ENTRY, port,   ASN1_INTEGER),
    ASN1_SIMPLE(PQC_CACHE_ENTRY, expiry, ASN1_INTEGER),
} ASN1_SEQUENCE_END(PQC_CACHE_ENTRY)

IMPLEMENT_ASN1_FUNCTIONS(PQC_CACHE_ENTRY)

/* -------------------------------------------------------------------------
 * Cache: in-memory operations + atomic file persistence
 *
 * The in-memory array (pctx->cache[]) is the authoritative state.
 * The file is written atomically (temp + rename) on every change.
 * Multiple processes sharing the same file are not explicitly coordinated
 * beyond the atomic rename; this is sufficient for the POC.
 * ---------------------------------------------------------------------- */

/* Find index of (host, port) in cache, or -1. Ignores expiry. */
static int pqc_cache_find(const pqc_ctx_t *pctx, const char *host, int port)
{
    int i;
    for (i = 0; i < pctx->ncache; i++)
        if (pctx->cache[i].port == port
                && strcmp(pctx->cache[i].host, host) == 0)
            return i;
    return -1;
}

/* Lookup: return 1 and set *expiry_out if a valid (unexpired) entry exists. */
static int pqc_cache_lookup(const pqc_ctx_t *pctx, const char *host, int port,
                             time_t *expiry_out)
{
    int i = pqc_cache_find(pctx, host, port);
    if (i < 0) return 0;
    if (pctx->cache[i].expiry <= time(NULL)) return 0;
    *expiry_out = pctx->cache[i].expiry;
    return 1;
}

/*
 * Persist the full in-memory cache to disk atomically (temp + rename).
 * No-op if cache is not enabled.
 */
static int pqc_cache_persist(pqc_ctx_t *pctx)
{
    char tmppath[528];
    BIO *wbio = NULL;
    int i, ret = 0;
#ifdef _WIN32
    const char *path = pctx->cache_path;
    snprintf(tmppath, sizeof(tmppath), "%s.tmp.XXXXXX", path);
    if (_mktemp_s(tmppath, sizeof(tmppath)) != 0) goto fail;
    wbio = BIO_new_file(tmppath, "w");
#else
    int fd;
    const char *path = pctx->cache_path;
    snprintf(tmppath, sizeof(tmppath), "%s.tmp.XXXXXX", path);
    fd = mkstemp(tmppath);
    if (fd < 0) goto fail;
    wbio = BIO_new_fd(fd, BIO_CLOSE);
#endif
    if (wbio == NULL) goto fail;

    for (i = 0; i < pctx->ncache; i++) {
        PQC_CACHE_ENTRY *e = PQC_CACHE_ENTRY_new();
        unsigned char *der = NULL;
        int derlen;
        if (e == NULL) continue;
        if (!ASN1_STRING_set(e->host, pctx->cache[i].host,
                             (int)strlen(pctx->cache[i].host))
                || !ASN1_INTEGER_set(e->port, pctx->cache[i].port)
                || !ASN1_INTEGER_set_int64(e->expiry,
                                           (int64_t)pctx->cache[i].expiry)) {
            PQC_CACHE_ENTRY_free(e);
            continue;
        }
        derlen = i2d_PQC_CACHE_ENTRY(e, &der);
        PQC_CACHE_ENTRY_free(e);
        if (derlen > 0) {
            PEM_write_bio(wbio, PQC_PEM_TYPE, "", der, derlen);
            OPENSSL_free(der);
        }
    }
    BIO_flush(wbio);
    BIO_free(wbio); wbio = NULL;

#ifdef _WIN32
    DeleteFileA(path);
    ret = MoveFileA(tmppath, path);
#else
    ret = (rename(tmppath, path) == 0);
#endif
    if (ret) return 1;
    unlink(tmppath);

fail:
    fprintf(stderr, "pqc_continuity: cache write failed for %s, disabling cache\n",
            pctx->cache_path);
    pctx->cache_enabled = 0;
    return 0;
}

/* Update or insert (host, port, expiry) in memory, then persist. */
/* Grow cache array if full. Returns 1 on success, 0 on alloc failure. */
static int pqc_cache_grow(pqc_ctx_t *pctx)
{
    int newcap = pctx->cache_cap == 0 ? PQC_CACHE_INIT : pctx->cache_cap * 2;
    pqc_entry_t *p = OPENSSL_realloc(pctx->cache,
                                      newcap * sizeof(pqc_entry_t));
    if (p == NULL) return 0;
    pctx->cache = p;
    pctx->cache_cap = newcap;
    return 1;
}

static int pqc_cache_update(pqc_ctx_t *pctx, const char *host, int port,
                             time_t expiry)
{
    int i = pqc_cache_find(pctx, host, port);
    if (i < 0) {
        if (pctx->ncache >= pctx->cache_cap && !pqc_cache_grow(pctx))
            return 0;
        i = pctx->ncache++;
        snprintf(pctx->cache[i].host, sizeof(pctx->cache[i].host), "%s", host);
        pctx->cache[i].port = port;
    }
    pctx->cache[i].expiry = expiry;
    if (pctx->cache_enabled)
        pqc_cache_persist(pctx);
    return 1;
}

/* Remove (host, port) from memory (swap with last), then persist. */
static int pqc_cache_delete(pqc_ctx_t *pctx, const char *host, int port)
{
    int i = pqc_cache_find(pctx, host, port);
    if (i < 0) return 0;
    pctx->cache[i] = pctx->cache[--pctx->ncache];
    if (pctx->cache_enabled)
        pqc_cache_persist(pctx);
    return 1;
}

/*
 * Load cache file into pctx->cache[] at init time.
 * Silently ignores missing file or malformed entries.
 */
static void pqc_cache_load(pqc_ctx_t *pctx)
{
    BIO *bio;
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long datalen;

    if (!pctx->cache_enabled) return;
    bio = BIO_new_file(pctx->cache_path, "r");
    if (bio == NULL) { ERR_clear_error(); return; }

    while (PEM_read_bio(bio, &name, &header, &data, &datalen) == 1) {
        if (strcmp(name, PQC_PEM_TYPE) == 0) {
            const unsigned char *p = data;
            PQC_CACHE_ENTRY *e = d2i_PQC_CACHE_ENTRY(NULL, &p, datalen);
            if (e != NULL) {
                int slen = e->host->length;
                int64_t port;
                int64_t expiry;
                if (slen > 0 && (size_t)slen < sizeof(pctx->cache[0].host)
                        && ASN1_INTEGER_get_int64(&port, e->port) == 1
                        && ASN1_INTEGER_get_int64(&expiry, e->expiry) == 1) {
                    if (pctx->ncache >= pctx->cache_cap
                            && !pqc_cache_grow(pctx)) {
                        PQC_CACHE_ENTRY_free(e);
                        break;
                    }
                    memcpy(pctx->cache[pctx->ncache].host,
                           e->host->data, slen);
                    pctx->cache[pctx->ncache].host[slen] = '\0';
                    pctx->cache[pctx->ncache].port   = (int)port;
                    pctx->cache[pctx->ncache].expiry = (time_t)expiry;
                    pctx->ncache++;
                }
                PQC_CACHE_ENTRY_free(e);
            }
        }
        OPENSSL_free(name); name = NULL;
        OPENSSL_free(header); header = NULL;
        OPENSSL_free(data); data = NULL;
    }
    ERR_clear_error();
    BIO_free(bio);
}

/* -------------------------------------------------------------------------
 * Build a colon-separated list of PQC sigalg names for SSL_set1_sigalgs_list.
 * Walks the SSL_CTX sigalg_lookup_cache; emits names whose scheme value is in
 * the PQC registry.  Returns 1 if at least one name was written, 0 otherwise.
 * ---------------------------------------------------------------------- */
static int pqc_build_sigalgs_list(SSL_CTX *ctx, char *buf, size_t buflen)
{
    size_t i;
    int n = 0;
    size_t pos = 0;

    if (ctx == NULL || buf == NULL || buflen == 0) return 0;
    buf[0] = '\0';

    for (i = 0; i < ctx->sigalg_lookup_cache_len; i++) {
        const SIGALG_LOOKUP *lu = &ctx->sigalg_lookup_cache[i];
        size_t nlen;

        if (lu->sigalg == 0 || lu->name == NULL) continue;
        if (pqc_alg_by_scheme(lu->sigalg) == NULL) continue;

        nlen = strlen(lu->name);
        if (pos + nlen + 2 > buflen) break;  /* +2 for ':' and NUL */
        if (n > 0) buf[pos++] = ':';
        memcpy(buf + pos, lu->name, nlen);
        pos += nlen;
        buf[pos] = '\0';
        n++;
    }
    return (n > 0) ? 1 : 0;
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

    if (pctx == NULL) return 0;

    if (context & SSL_EXT_CLIENT_HELLO) {
        char host[256];
        int port = 0;
        time_t cached_expiry = 0;

        if (SSL_is_server(s)) return 0;

        /*
         * Cache hit: restrict this connection to PQC signature algorithms only.
         * This is the core downgrade-prevention mechanism — the client will not
         * offer traditional sigalgs to a server it has previously seen with a
         * PQC certificate.
         */
        pqc_get_host_port(s, host, sizeof(host), &port);
        if (pqc_cache_lookup(pctx, host, port, &cached_expiry)) {
            char sigalgs[512];
            if (pqc_build_sigalgs_list(SSL_get_SSL_CTX(s), sigalgs,
                                       sizeof(sigalgs)))
                SSL_set1_sigalgs_list(s, sigalgs);
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
        scheme = pqc_pkey_to_scheme(SSL_get_SSL_CTX(s), pkey);
        if (scheme == 0 || pctx->validity_period == 0) {
            /*
             * Traditional cert, or no ValidityPeriod configured: send empty
             * extension as a presence signal only — no cache instruction.
             * (validity_period == 0 on the wire means "clear cache", so we
             * must not send it unless explicitly configured.)
             */
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

    if (pctx == NULL) return 1;

    if (context & SSL_EXT_CLIENT_HELLO)
        return 1; /* server notes client support; no payload */

    if (context & SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        if (!SSL_is_server(s))
            pctx->server_sent_cr = 1;
        return 1;
    }

    if (context & SSL_EXT_TLS1_3_CERTIFICATE) {
        char host[256];
        int port = 0;

        if (chainidx != 0) return 1;

        pqc_get_host_port(s, host, sizeof(host), &port);

        if (inlen == 0) {
            /*
             * Empty extension: server signals PQC support but sends no cache
             * instruction.  If we have a cache entry for this host:port and
             * the server sent no PQC cert, that is a downgrade — abort.
             */
            time_t cached_expiry = 0;
            if (!SSL_is_server(s)
                    && pqc_cache_lookup(pctx, host, port, &cached_expiry)) {
                *al = SSL_AD_HANDSHAKE_FAILURE;
                return 0; /* downgrade detected */
            }
            return 1;
        }

        if (inlen != PQC_EXT_DATA_LEN) { *al = SSL_AD_DECODE_ERROR; return 0; }

        {
            uint16_t scheme   = ((uint16_t)in[0] << 8) | (uint16_t)in[1];
            uint32_t validity = ((uint32_t)in[2] << 24) | ((uint32_t)in[3] << 16)
                              | ((uint32_t)in[4] <<  8) |  (uint32_t)in[5];

            if (pqc_alg_by_scheme(scheme) == NULL)
                return 1; /* not a known PQC alg: ignore per §3.3 */

            if (validity == 0)
                pqc_cache_delete(pctx, host, port);
            else
                pqc_cache_update(pctx, host, port,
                                 time(NULL) + (time_t)validity);
        }
    }

    return 1;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

int pqc_cont_init(SSL_CTX *ctx)
{
    pqc_ctx_t *pctx;
    int section_found = 0;
    unsigned int contexts;

    pctx = OPENSSL_zalloc(sizeof(*pctx));
    if (pctx == NULL) return 0;

    /* validity_period stays 0 until set by ValidityPeriod in config */

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
                    if (strcasecmp(val, "no") == 0) {
                        NCONF_free(conf);
                        OPENSSL_free(pctx->cache);
                        OPENSSL_free(pctx);
                        return 1; /* explicitly disabled: do not register extension */
                    }
                } else {
                    ERR_clear_error();
                }

                val = NCONF_get_string(conf, "pqc_continuity", "ValidityPeriod");
                if (val != NULL) {
                    section_found = 1;
                    pctx->validity_period = (uint32_t)strtoul(val, NULL, 10);
                } else {
                    ERR_clear_error();
                }

                val = NCONF_get_string(conf, "pqc_continuity", "CachePath");
                if (val != NULL) {
                    section_found = 1;
                    snprintf(pctx->cache_path, sizeof(pctx->cache_path), "%s", val);
                    pctx->cache_enabled = 1;
                } else {
                    ERR_clear_error();
                }
            }
            NCONF_free(conf);
            ERR_clear_error();
        }
    }

    if (!section_found) {
        OPENSSL_free(pctx->cache);
        OPENSSL_free(pctx);
        return 1; /* no config section: silently disabled */
    }

    pqc_cache_load(pctx);

    contexts = SSL_EXT_CLIENT_HELLO
             | SSL_EXT_TLS1_3_CERTIFICATE_REQUEST
             | SSL_EXT_TLS1_3_CERTIFICATE;

    if (!SSL_CTX_add_custom_ext(ctx, TLSEXT_TYPE_pq_cert_available, contexts,
                                 pqc_add_cb, pqc_free_cb, pctx,
                                 pqc_parse_cb, pctx)) {
        OPENSSL_free(pctx->cache);
        OPENSSL_free(pctx);
        return 0;
    }

    return 1;
}
