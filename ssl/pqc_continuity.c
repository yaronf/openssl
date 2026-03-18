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

/*
 * Debug bitmask (Debug config key, hex) for fault injection in tests.
 * See docs/POC-PLAN.md § Debug Bitmask.
 */
#define PQC_DEBUG_WRONG_SCHEME     0x02  /* server sends mismatched PQC scheme */
#define PQC_DEBUG_LEGACY_SCHEME    0x04  /* server sends RSA scheme in CT */
#define PQC_DEBUG_MALFORMED_EXT    0x08  /* server sends wrong-length CT ext */
#define PQC_DEBUG_UNKNOWN_SCHEME        0x10  /* server sends unregistered scheme */
#define PQC_DEBUG_CT_ON_INTERMEDIATE    0x40  /* server sends CT on intermediate cert (chainidx 1) */

/* Per-context state, passed via add_arg / parse_arg. */
typedef struct {
    uint32_t     validity_period;
    char         cache_path[512];
    int          cache_enabled; /* 1 if CachePath was set; 0 = no persistence */
    int          server_sent_cr;
    uint32_t     debug_mask;  /* fault injection bitmask; 0 in production */
    pqc_entry_t *cache;     /* heap-allocated, grown with OPENSSL_realloc */
    int          ncache;
    int          cache_cap;
} pqc_ctx_t;

/*
 * Per-connection pending cache intent.
 *
 * The CT parse_cb fires during tls_process_server_certificate(), before
 * ssl_verify_cert_chain() runs.  We must not write the cache until we know
 * the peer's certificate chain is trusted.  This struct holds the intent
 * (update or delete) and is flushed in pqc_info_cb() at SSL_CB_HANDSHAKE_DONE
 * only if SSL_get_verify_result() == X509_V_OK.
 *
 * Stored as SSL ex_data (index pqc_conn_ex_idx).
 */
typedef enum {
    PQC_PENDING_NONE   = 0,
    PQC_PENDING_UPDATE = 1,  /* write/refresh cache entry */
    PQC_PENDING_DELETE = 2   /* remove cache entry (validity == 0) */
} pqc_pending_op_t;

typedef struct {
    pqc_ctx_t       *pctx;         /* back-pointer to per-context state */
    pqc_pending_op_t op;
    char             host[256];
    int              port;
    time_t           expiry;       /* only valid for PQC_PENDING_UPDATE */
    int              client_sent_ch; /* server-side: 1 if client included CH ext */
    int (*prev_verify_cb)(int, X509_STORE_CTX *); /* chained verify callback */
} pqc_conn_t;

/* SSL ex_data index for pqc_conn_t; initialised once in pqc_cont_init(). */
static int pqc_conn_ex_idx = -1;

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
    {
        static int warned = 0;
        if (!warned) {
            warned = 1;
            fprintf(stderr, "pqc_continuity: cache write failed for %s, disabling cache\n",
                    pctx->cache_path);
        }
    }
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
    } else if (expiry < pctx->cache[i].expiry) {
        /* Draft 3.3: SHOULD NOT accept a decrease in validity period.
         * Leave the existing (longer) expiry untouched. */
        fprintf(stderr, "pqc_continuity: ignoring validity decrease for %s:%d "
                "(cached=%ld, offered=%ld)\n",
                host, port, (long)pctx->cache[i].expiry, (long)expiry);
        return 1;
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
 * Per-connection ex_data lifecycle
 * ---------------------------------------------------------------------- */

static void pqc_conn_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp)
{
    OPENSSL_free(ptr);
}

/*
 * Return (allocating if necessary) the pqc_conn_t for this SSL object.
 * Returns NULL on allocation failure.
 */
static pqc_conn_t *pqc_conn_get_or_create(SSL *s, pqc_ctx_t *pctx)
{
    pqc_conn_t *conn;

    if (pqc_conn_ex_idx < 0) return NULL;
    conn = SSL_get_ex_data(s, pqc_conn_ex_idx);
    if (conn != NULL) return conn;

    conn = OPENSSL_zalloc(sizeof(*conn));
    if (conn == NULL) return NULL;
    conn->pctx = pctx;
    if (!SSL_set_ex_data(s, pqc_conn_ex_idx, conn)) {
        OPENSSL_free(conn);
        return NULL;
    }
    return conn;
}

/* -------------------------------------------------------------------------
 * Verify callback — fires for each cert during ssl_verify_cert_chain().
 *
 * If the EE cert carried a PQC extension (pending op is set), we require
 * every cert in the chain to be PQC.  A non-PQC cert in the chain while
 * the EE is PQC indicates a mixed chain — possible CRQC attack on an
 * intermediate CA.  We abort by returning 0 (verification failure).
 *
 * Chains the previous per-SSL verify callback if one was installed.
 * ---------------------------------------------------------------------- */

static int pqc_verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
    SSL *ssl;
    pqc_conn_t *conn;
    X509 *cert;
    EVP_PKEY *pkey;

    /* Run the previous verify callback first (if any). */
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (ssl != NULL && pqc_conn_ex_idx >= 0) {
        conn = SSL_get_ex_data(ssl, pqc_conn_ex_idx);
        if (conn != NULL && conn->prev_verify_cb != NULL) {
            preverify_ok = conn->prev_verify_cb(preverify_ok, ctx);
        }
    }

    if (!preverify_ok) return 0;  /* already failing; don't pile on */
    if (ssl == NULL || pqc_conn_ex_idx < 0) return preverify_ok;

    conn = SSL_get_ex_data(ssl, pqc_conn_ex_idx);
    if (conn == NULL || conn->op == PQC_PENDING_NONE) return preverify_ok;

    /* Mixed-chain check: current cert must be PQC. */
    cert = X509_STORE_CTX_get_current_cert(ctx);
    pkey = cert ? X509_get0_pubkey(cert) : NULL;
    if (pqc_pkey_to_scheme(SSL_get_SSL_CTX(ssl), pkey) == 0) {
        char subj[256] = "(unknown)";
        if (cert)
            X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
        fprintf(stderr, "pqc_continuity: mixed chain: non-PQC cert \"%s\" — aborting\n", subj);
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
        return 0;
    }
    return preverify_ok;
}

/* -------------------------------------------------------------------------
 * Info callback — fires at SSL_CB_HANDSHAKE_DONE.
 * Flushes the pending cache intent only if cert verification succeeded.
 * Chains the CTX-level info callback so apps using -state/-msg still work.
 * ---------------------------------------------------------------------- */

static void pqc_info_cb(const SSL *ssl, int where, int ret)
{
    /* Chain CTX-level callback first (it was there before we set ours). */
    {
        void (*ctx_cb)(const SSL *, int, int) =
            SSL_CTX_get_info_callback(SSL_get_SSL_CTX(ssl));
        if (ctx_cb != NULL && ctx_cb != pqc_info_cb)
            ctx_cb(ssl, where, ret);
    }

    if (where != SSL_CB_HANDSHAKE_DONE) return;

    /* Only flush on the client side: server's peer cert (client auth) is a
     * separate concern; skip for now (H4 semantics undefined in draft). */
    if (SSL_is_server(ssl)) return;

    {
        pqc_conn_t *conn;
        long vresult;

        if (pqc_conn_ex_idx < 0) return;
        conn = SSL_get_ex_data(ssl, pqc_conn_ex_idx);
        if (conn == NULL || conn->op == PQC_PENDING_NONE) return;

        vresult = SSL_get_verify_result(ssl);
        fprintf(stderr, "pqc_continuity: handshake done, verify_result=%ld (%s), pending_op=%d for %s:%d\n",
                vresult, (vresult == X509_V_OK ? "OK" : "FAIL"),
                conn->op, conn->host, conn->port);

        if (vresult != X509_V_OK) {
            fprintf(stderr, "pqc_continuity: discarding pending cache write — cert verification failed\n");
            conn->op = PQC_PENDING_NONE;
            return;
        }

        if (conn->op == PQC_PENDING_UPDATE)
            pqc_cache_update(conn->pctx, conn->host, conn->port, conn->expiry);
        else if (conn->op == PQC_PENDING_DELETE)
            pqc_cache_delete(conn->pctx, conn->host, conn->port);

        conn->op = PQC_PENDING_NONE;
    }
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
        /*
         * Install our per-SSL info callback now, before any app callback is
         * set on this SSL object.  pqc_info_cb chains the CTX-level callback
         * so apps using -state/-msg continue to work.
         */
        SSL_set_info_callback(s, pqc_info_cb);

        /*
         * Install per-SSL verify callback for mixed-chain detection.
         * Chains the existing per-SSL verify callback (if any).
         * pqc_verify_cb is a no-op until parse_cb sets op != PQC_PENDING_NONE.
         */
        {
            pqc_conn_t *conn = pqc_conn_get_or_create(s, pctx);
            if (conn != NULL) {
                conn->prev_verify_cb = SSL_get_verify_callback(s);
                SSL_set_verify(s, SSL_get_verify_mode(s), pqc_verify_cb);
            }
        }

        pqc_get_host_port(s, host, sizeof(host), &port);
        fprintf(stderr, "pqc_continuity: CH add_cb host=%s port=%d ncache=%d\n",
                host, port, pctx->ncache);
        if (pqc_cache_lookup(pctx, host, port, &cached_expiry)) {
            char sigalgs[512];
            SSL_CTX *sctx = SSL_get_SSL_CTX(s);
            fprintf(stderr, "pqc_continuity: cache hit for %s:%d expiry=%ld, building sigalgs list (cache_len=%zu)\n",
                    host, port, (long)cached_expiry, sctx->sigalg_lookup_cache_len);
            if (pqc_build_sigalgs_list(sctx, sigalgs, sizeof(sigalgs))) {
                fprintf(stderr, "pqc_continuity: restricting sigalgs to: %s\n", sigalgs);
                SSL_set1_sigalgs_list(s, sigalgs);
            } else {
                fprintf(stderr, "pqc_continuity: pqc_build_sigalgs_list returned 0 (no PQC sigalgs in lookup cache)\n");
                /* Dump first few entries to diagnose */
                {
                    size_t k;
                    for (k = 0; k < sctx->sigalg_lookup_cache_len && k < 20; k++) {
                        const SIGALG_LOOKUP *lu = &sctx->sigalg_lookup_cache[k];
                        fprintf(stderr, "  sigalg_lookup_cache[%zu]: sigalg=0x%04x name=%s sig=%d\n",
                                k, lu->sigalg, lu->name ? lu->name : "(null)", lu->sig);
                    }
                }
            }
        } else {
            fprintf(stderr, "pqc_continuity: no cache hit for %s:%d\n", host, port);
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

        /* Debug: CT_ON_INTERMEDIATE — inject CT on the intermediate (chainidx 1),
         * skipping chainidx 0 entirely so the extension lands in the wrong place. */
        if (pctx->debug_mask & PQC_DEBUG_CT_ON_INTERMEDIATE) {
            if (chainidx != 1) return 0;
            fprintf(stderr, "pqc_continuity: [debug] CT_ON_INTERMEDIATE — injecting CT on chainidx 1\n");
            /* Fall through to normal CT encoding below (using chainidx 1's cert). */
        } else if (chainidx != 0) {
            return 0;
        }

        /*
         * Server: only send CT if client included the CH extension (P1).
         * If client did not send CH, server must not send CT.
         */
        if (SSL_is_server(s)) {
            pqc_conn_t *conn = (pqc_conn_ex_idx >= 0)
                               ? SSL_get_ex_data(s, pqc_conn_ex_idx) : NULL;
            if (conn == NULL || !conn->client_sent_ch) {
                fprintf(stderr, "pqc_continuity: server skipping CT — client did not send CH\n");
                return 0;
            }
        }

        pkey = (x != NULL) ? X509_get0_pubkey(x) : NULL;
        scheme = pqc_pkey_to_scheme(SSL_get_SSL_CTX(s), pkey);
        if (scheme == 0) {
            /*
             * Traditional cert: send empty extension as a presence signal only.
             * The client's parse_cb will check for a downgrade if it has a
             * cache entry for this host:port.
             */
            *out = NULL; *outlen = 0;
            return 1;
        }

        /* Debug: WRONG_SCHEME — send a different known PQC scheme.
         * Pick the next ML-DSA level (wraps within the ML-DSA range). */
        if (pctx->debug_mask & PQC_DEBUG_WRONG_SCHEME) {
            uint16_t wrong;
            fprintf(stderr, "pqc_continuity: [debug] WRONG_SCHEME — sending mismatched scheme\n");
            /* Cycle within ML-DSA: 44→65→87→44 */
            if      (scheme == PQC_MLDSA44) wrong = PQC_MLDSA65;
            else if (scheme == PQC_MLDSA65) wrong = PQC_MLDSA87;
            else                             wrong = PQC_MLDSA44;
            buf = OPENSSL_malloc(PQC_EXT_DATA_LEN);
            if (buf == NULL) { *al = SSL_AD_INTERNAL_ERROR; return -1; }
            buf[0] = (wrong >> 8) & 0xff;
            buf[1] =  wrong       & 0xff;
            buf[2] = (pctx->validity_period >> 24) & 0xff;
            buf[3] = (pctx->validity_period >> 16) & 0xff;
            buf[4] = (pctx->validity_period >>  8) & 0xff;
            buf[5] =  pctx->validity_period        & 0xff;
            *out = buf; *outlen = PQC_EXT_DATA_LEN;
            return 1;
        }

        /* Debug: LEGACY_SCHEME — send rsa_pkcs1_sha256 (0x0401) in the extension. */
        if (pctx->debug_mask & PQC_DEBUG_LEGACY_SCHEME) {
            fprintf(stderr, "pqc_continuity: [debug] LEGACY_SCHEME — sending RSA scheme 0x0401\n");
            buf = OPENSSL_malloc(PQC_EXT_DATA_LEN);
            if (buf == NULL) { *al = SSL_AD_INTERNAL_ERROR; return -1; }
            buf[0] = 0x04; buf[1] = 0x01;  /* rsa_pkcs1_sha256 */
            buf[2] = (pctx->validity_period >> 24) & 0xff;
            buf[3] = (pctx->validity_period >> 16) & 0xff;
            buf[4] = (pctx->validity_period >>  8) & 0xff;
            buf[5] =  pctx->validity_period        & 0xff;
            *out = buf; *outlen = PQC_EXT_DATA_LEN;
            return 1;
        }

        /* Debug: MALFORMED_EXT — send extension with wrong length (3 bytes). */
        if (pctx->debug_mask & PQC_DEBUG_MALFORMED_EXT) {
            fprintf(stderr, "pqc_continuity: [debug] MALFORMED_EXT — sending 3-byte extension\n");
            buf = OPENSSL_malloc(3);
            if (buf == NULL) { *al = SSL_AD_INTERNAL_ERROR; return -1; }
            buf[0] = (scheme >> 8) & 0xff;
            buf[1] =  scheme       & 0xff;
            buf[2] = 0x42;  /* truncated — not a valid 6-byte extension */
            *out = buf; *outlen = 3;
            return 1;
        }

        /* Debug: UNKNOWN_SCHEME — send an unregistered scheme value. */
        if (pctx->debug_mask & PQC_DEBUG_UNKNOWN_SCHEME) {
            fprintf(stderr, "pqc_continuity: [debug] UNKNOWN_SCHEME — sending scheme 0xFE42\n");
            buf = OPENSSL_malloc(PQC_EXT_DATA_LEN);
            if (buf == NULL) { *al = SSL_AD_INTERNAL_ERROR; return -1; }
            buf[0] = 0xFE; buf[1] = 0x42;  /* not in pqc_alg_registry */
            buf[2] = (pctx->validity_period >> 24) & 0xff;
            buf[3] = (pctx->validity_period >> 16) & 0xff;
            buf[4] = (pctx->validity_period >>  8) & 0xff;
            buf[5] =  pctx->validity_period        & 0xff;
            *out = buf; *outlen = PQC_EXT_DATA_LEN;
            return 1;
        }

        if (pctx->validity_period == 0) {
            /*
             * PQC cert + ValidityPeriod = 0: explicitly instruct the client to
             * clear its cache entry for this host:port.  Send the full extension
             * with validity = 0; an empty extension would be misread as a
             * traditional-cert downgrade by a client that has a cache entry.
             */
            buf = OPENSSL_malloc(PQC_EXT_DATA_LEN);
            if (buf == NULL) { *al = SSL_AD_INTERNAL_ERROR; return -1; }
            buf[0] = (scheme >> 8) & 0xff;
            buf[1] =  scheme       & 0xff;
            buf[2] = buf[3] = buf[4] = buf[5] = 0;   /* validity = 0 */
            *out = buf; *outlen = PQC_EXT_DATA_LEN;
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

    if (context & SSL_EXT_CLIENT_HELLO) {
        /*
         * Server notes that client supports the extension.
         * Store in per-connection state so CT add_cb can gate on it.
         */
        if (SSL_is_server(s)) {
            pqc_conn_t *conn = pqc_conn_get_or_create(s, pctx);
            if (conn != NULL)
                conn->client_sent_ch = 1;
        }
        return 1;
    }

    if (context & SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        if (!SSL_is_server(s))
            pctx->server_sent_cr = 1;
        return 1;
    }

    if (context & SSL_EXT_TLS1_3_CERTIFICATE) {
        char host[256];
        int port = 0;

        if (chainidx != 0) {
            /* CT extension on a non-EE CertificateEntry is a protocol violation. */
            if (!SSL_is_server(s)) {
                fprintf(stderr, "pqc_continuity: CT extension on chainidx %zu (not EE) — aborting\n",
                        chainidx);
                *al = SSL_AD_ILLEGAL_PARAMETER;
                return 0;
            }
            return 1;
        }

        pqc_get_host_port(s, host, sizeof(host), &port);

        if (inlen == 0) {
            /*
             * Empty extension: server signals PQC support but sends no cache
             * instruction (traditional cert).  Two checks on the client side:
             *
             * 1. Downgrade: if we have a cache entry for this host:port the
             *    server previously had a PQC cert — abort.
             *
             * 2. Mixed chain: if the client has a cache entry and the server
             *    is sending a traditional cert with a non-PQC chain, that is
             *    also a downgrade — abort.  (The chain check for the non-empty
             *    case is below; this handles the cached-sender path.)
             */
            if (!SSL_is_server(s)) {
                time_t cached_expiry = 0;
                if (pqc_cache_lookup(pctx, host, port, &cached_expiry)) {
                    *al = SSL_AD_HANDSHAKE_FAILURE;
                    return 0; /* downgrade detected */
                }
            }
            return 1;
        }

        if (inlen != PQC_EXT_DATA_LEN) { *al = SSL_AD_DECODE_ERROR; return 0; }

        {
            uint16_t scheme   = ((uint16_t)in[0] << 8) | (uint16_t)in[1];
            uint32_t validity = ((uint32_t)in[2] << 24) | ((uint32_t)in[3] << 16)
                              | ((uint32_t)in[4] <<  8) |  (uint32_t)in[5];

            /*
             * The scheme in the extension must exactly match the cert's actual
             * public key.  Any deviation — wrong PQC alg, legacy alg, or
             * unknown value — is treated as tampering: abort with
             * illegal_parameter.  There is no forward-compat carve-out for
             * unknown schemes; if the server sends an extension it must be
             * consistent with the cert it is presenting.
             */
            if (!SSL_is_server(s)) {
                EVP_PKEY *pkey = x != NULL ? X509_get0_pubkey(x) : NULL;
                uint16_t cert_scheme = pqc_pkey_to_scheme(SSL_get_SSL_CTX(s), pkey);
                if (cert_scheme == 0 || cert_scheme != scheme) {
                    fprintf(stderr, "pqc_continuity: CT parse_cb scheme mismatch: "
                            "extension=0x%04x cert=0x%04x — aborting\n",
                            scheme, cert_scheme);
                    *al = SSL_AD_ILLEGAL_PARAMETER;
                    return 0;
                }
            }

            /*
             * Do NOT write the cache here.  This callback fires before
             * ssl_verify_cert_chain() — the peer's cert is not yet verified.
             * Record the intent; pqc_info_cb() flushes it at
             * SSL_CB_HANDSHAKE_DONE after confirming X509_V_OK.
             */
            {
                pqc_conn_t *conn = pqc_conn_get_or_create(s, pctx);
                if (conn != NULL) {
                    snprintf(conn->host, sizeof(conn->host), "%s", host);
                    conn->port = port;
                    if (validity == 0) {
                        conn->op = PQC_PENDING_DELETE;
                    } else {
                        conn->op     = PQC_PENDING_UPDATE;
                        conn->expiry = time(NULL) + (time_t)validity;
                    }
                    fprintf(stderr, "pqc_continuity: CT parse_cb deferring cache %s for %s:%d\n",
                            validity == 0 ? "delete" : "update", host, port);
                }
            }
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

    /* Register SSL ex_data slot once (idempotent via CRYPTO_get_ex_new_index). */
    if (pqc_conn_ex_idx < 0) {
        pqc_conn_ex_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL,
                                                pqc_conn_free);
        if (pqc_conn_ex_idx < 0) return 0;
    }

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

                val = NCONF_get_string(conf, "pqc_continuity", "Debug");
                if (val != NULL) {
                    section_found = 1;
                    pctx->debug_mask = (uint32_t)strtoul(val, NULL, 16);
                    if (pctx->debug_mask != 0)
                        fprintf(stderr, "pqc_continuity: debug_mask=0x%02x (fault injection active)\n",
                                pctx->debug_mask);
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
