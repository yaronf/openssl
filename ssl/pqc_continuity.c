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
#include "internal/thread_once.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#ifndef _WIN32
# include <sys/socket.h>
# include <sys/file.h>   /* flock */
# include <netinet/in.h>
# include <fcntl.h>      /* O_WRONLY, O_CREAT */
# include <unistd.h>     /* close */
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
#define PQC_DEBUG_CT_ON_INTERMEDIATE    0x40  /* server sends CT on both EE (chainidx 0) AND intermediate (chainidx 1) */
#define PQC_DEBUG_CT_ONLY_INTERMEDIATE  0x80  /* server sends CT on intermediate (chainidx 1) ONLY, skipping EE */

/*
 * Per-path global cache.  One instance per unique CachePath value across all
 * SSL_CTX objects in the process.  In practice always a single instance.
 * Protected by its own CRYPTO_RWLOCK: read lock for lookup, write lock for
 * update/delete/persist/load.
 */
#define PQC_MAX_CACHES 4

typedef struct {
    char          path[512];
    int           enabled;
    pqc_entry_t  *entries;
    int           nentries;
    int           cap;
    CRYPTO_RWLOCK *lock;
} pqc_gcache_t;

static pqc_gcache_t   pqc_caches[PQC_MAX_CACHES];
static int            pqc_ncaches    = 0;
static CRYPTO_RWLOCK *pqc_reg_lock   = NULL; /* protects pqc_caches[] registry */
static CRYPTO_ONCE    pqc_reg_once   = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(pqc_reg_init)
{
    pqc_reg_lock = CRYPTO_THREAD_lock_new();
    return (pqc_reg_lock != NULL);
}

/*
 * Per-context state, passed via add_arg / parse_arg.
 * Cache fields have moved to pqc_gcache_t; pctx holds only per-CTX config.
 * cache_idx is the index into pqc_caches[], or -1 if caching is disabled.
 */
typedef struct {
    uint32_t validity_period;
    uint32_t debug_mask;  /* fault injection bitmask; 0 in production */
    int      cache_idx;   /* index into pqc_caches[], or -1 */
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
    int              server_sent_cr; /* client-side: 1 if server included CR ext */
    int (*prev_verify_cb)(int, X509_STORE_CTX *); /* chained verify callback */
} pqc_conn_t;

/*
 * SSL ex_data index for pqc_conn_t.
 * Initialised exactly once (thread-safe) via CRYPTO_THREAD_run_once.
 */
static int         pqc_conn_ex_idx  = -1;
static CRYPTO_ONCE pqc_ex_idx_once  = CRYPTO_ONCE_STATIC_INIT;

/* Forward declarations. */
static void pqc_conn_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp);
static pqc_gcache_t *pqc_get_gcache(const pqc_ctx_t *pctx);

DEFINE_RUN_ONCE_STATIC(pqc_ex_idx_init)
{
    pqc_conn_ex_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, pqc_conn_free);
    return (pqc_conn_ex_idx >= 0);
}

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

/*
 * Dynamic sigalg registry — runtime extension via pqc_cont_register_sigalg().
 * Protected by pqc_dyn_lock (readers during lookup, writer during registration).
 * Note: the registry is used only for pqc_build_sigalgs_list() and
 * pqc_pkey_to_scheme(); parse_cb validation is done by cert-key comparison,
 * not by registry membership.
 */
static pqc_alg_t    *pqc_dyn_registry  = NULL;
static int           pqc_dyn_nalloc    = 0;
static int           pqc_dyn_nentries  = 0;
static CRYPTO_RWLOCK *pqc_dyn_lock     = NULL;
static CRYPTO_ONCE   pqc_dyn_lock_once = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(pqc_dyn_lock_init)
{
    pqc_dyn_lock = CRYPTO_THREAD_lock_new();
    return (pqc_dyn_lock != NULL);
}

/*
 * Register an additional PQC sigalg at runtime (e.g., from a provider).
 * Returns 1 on success, 0 on failure.
 */
int pqc_cont_register_sigalg(uint16_t scheme)
{
    pqc_alg_t *p;
    int ret = 0;

    if (scheme == 0) return 0;
    if (!RUN_ONCE(&pqc_dyn_lock_once, pqc_dyn_lock_init)) return 0;
    if (!CRYPTO_THREAD_write_lock(pqc_dyn_lock)) return 0;

    if (pqc_dyn_nentries >= pqc_dyn_nalloc) {
        int newalloc = pqc_dyn_nalloc == 0 ? 4 : pqc_dyn_nalloc * 2;
        p = OPENSSL_realloc(pqc_dyn_registry, newalloc * sizeof(pqc_alg_t));
        if (p != NULL) {
            pqc_dyn_registry = p;
            pqc_dyn_nalloc = newalloc;
        }
    }
    if (pqc_dyn_nentries < pqc_dyn_nalloc) {
        pqc_dyn_registry[pqc_dyn_nentries].scheme = scheme;
        pqc_dyn_nentries++;
        ret = 1;
    }

    CRYPTO_THREAD_unlock(pqc_dyn_lock);
    return ret;
}

/* Look up a scheme value in the combined (static + dynamic) registry. */
static const pqc_alg_t *pqc_alg_by_scheme(uint16_t scheme)
{
    int i;
    const pqc_alg_t *found = NULL;

    for (i = 0; pqc_alg_registry[i].scheme != 0; i++)
        if (pqc_alg_registry[i].scheme == scheme)
            return &pqc_alg_registry[i];

    /* Dynamic registry requires lock. */
    if (pqc_dyn_lock != NULL && CRYPTO_THREAD_read_lock(pqc_dyn_lock)) {
        for (i = 0; i < pqc_dyn_nentries; i++) {
            if (pqc_dyn_registry[i].scheme == scheme) {
                found = &pqc_dyn_registry[i];
                break;
            }
        }
        CRYPTO_THREAD_unlock(pqc_dyn_lock);
    }
    return found;
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
 * All functions operate on pqc_gcache_t.  Callers are responsible for holding
 * the appropriate lock (read for lookup, write for mutating operations).
 * pqc_cache_lookup and pqc_cache_update/delete acquire locks internally so
 * call sites don't need to.
 * ---------------------------------------------------------------------- */

/* Must be called with gc->lock write-held (or at single-threaded init). */
static int pqc_gcache_grow(pqc_gcache_t *gc)
{
    int newcap = gc->cap == 0 ? PQC_CACHE_INIT : gc->cap * 2;
    pqc_entry_t *p = OPENSSL_realloc(gc->entries, newcap * sizeof(pqc_entry_t));
    if (p == NULL) return 0;
    gc->entries = p;
    gc->cap = newcap;
    return 1;
}

/* Find index of (host, port) in gc, or -1.  Must be called with lock held. */
static int pqc_gcache_find(const pqc_gcache_t *gc, const char *host, int port)
{
    int i;
    for (i = 0; i < gc->nentries; i++)
        if (gc->entries[i].port == port
                && strcmp(gc->entries[i].host, host) == 0)
            return i;
    return -1;
}

/*
 * Persist the full in-memory cache to disk atomically (temp + rename),
 * protected by a per-path .lock file for cross-process serialization.
 * Must be called with gc->lock write-held.
 * No-op if cache is not enabled.
 */
static int pqc_gcache_persist(pqc_gcache_t *gc)
{
    _Static_assert(sizeof(((pqc_gcache_t *)0)->path) + 12 <= 528,
                   "tmppath buffer too small");
    _Static_assert(sizeof(((pqc_gcache_t *)0)->path) + 8  <= 524,
                   "lockpath buffer too small");

    char tmppath[sizeof(((pqc_gcache_t *)0)->path) + 12];
    char lockpath[sizeof(((pqc_gcache_t *)0)->path) + 8];
    const char *path = gc->path;
    BIO *wbio = NULL;
    int i, ret = 0;
#ifndef _WIN32
    int lockfd = -1;
    int fd;
#endif

    snprintf(lockpath, sizeof(lockpath), "%s.lock", path);
    snprintf(tmppath,  sizeof(tmppath),  "%s.tmp.XXXXXX", path);

#ifdef _WIN32
    /* Cross-process locking on Windows: best-effort; LockFileEx omitted for brevity. */
    if (_mktemp_s(tmppath, sizeof(tmppath)) != 0) goto fail;
    wbio = BIO_new_file(tmppath, "w");
#else
    lockfd = open(lockpath, O_WRONLY | O_CREAT, 0600);
    if (lockfd < 0) goto fail;
    if (flock(lockfd, LOCK_EX) != 0) goto fail;

    fd = mkstemp(tmppath);
    if (fd < 0) goto fail;
    wbio = BIO_new_fd(fd, BIO_CLOSE);
#endif
    if (wbio == NULL) goto fail;

    for (i = 0; i < gc->nentries; i++) {
        PQC_CACHE_ENTRY *e = PQC_CACHE_ENTRY_new();
        unsigned char *der = NULL;
        int derlen;
        if (e == NULL) continue;
        if (!ASN1_STRING_set(e->host, gc->entries[i].host,
                             (int)strlen(gc->entries[i].host))
                || !ASN1_INTEGER_set(e->port, gc->entries[i].port)
                || !ASN1_INTEGER_set_int64(e->expiry,
                                           (int64_t)gc->entries[i].expiry)) {
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
    BIO_free(wbio); wbio = NULL;

#ifdef _WIN32
    DeleteFileA(path);
    ret = MoveFileA(tmppath, path);
#else
    ret = (rename(tmppath, path) == 0);
    flock(lockfd, LOCK_UN);
    close(lockfd); lockfd = -1;
#endif
    if (ret) return 1;
#ifndef _WIN32
    unlink(tmppath);
#endif

fail:
#ifndef _WIN32
    if (lockfd >= 0) { flock(lockfd, LOCK_UN); close(lockfd); }
#endif
    if (wbio != NULL) { BIO_free(wbio); unlink(tmppath); }
    {
        static int warned = 0;
        if (!warned) {
            warned = 1;
            fprintf(stderr, "pqc_continuity: cache write failed for %s, "
                    "disabling cache\n", path);
        }
    }
    gc->enabled = 0;
    return 0;
}

/* Lookup: acquires read lock.  Returns 1 and sets *expiry_out if valid entry found. */
static int pqc_cache_lookup(pqc_gcache_t *gc, const char *host, int port,
                             time_t *expiry_out)
{
    int i, found = 0;
    if (gc == NULL || !gc->enabled) return 0;
    if (!CRYPTO_THREAD_read_lock(gc->lock)) return 0;
    i = pqc_gcache_find(gc, host, port);
    if (i >= 0 && gc->entries[i].expiry > time(NULL)) {
        *expiry_out = gc->entries[i].expiry;
        found = 1;
    }
    CRYPTO_THREAD_unlock(gc->lock);
    return found;
}

/* Update or insert.  Acquires write lock.  Returns 1 on success. */
static int pqc_cache_update(pqc_gcache_t *gc, const char *host, int port,
                             time_t expiry, uint32_t debug_mask)
{
    int i, ret = 1;
    if (gc == NULL) return 0;
    if (!CRYPTO_THREAD_write_lock(gc->lock)) return 0;

    i = pqc_gcache_find(gc, host, port);
    if (i < 0) {
        if (gc->nentries >= gc->cap && !pqc_gcache_grow(gc)) { ret = 0; goto done; }
        i = gc->nentries++;
        snprintf(gc->entries[i].host, sizeof(gc->entries[i].host), "%s", host);
        gc->entries[i].port = port;
    } else if (expiry < gc->entries[i].expiry) {
        /* Draft 3.3: SHOULD NOT accept a decrease in validity period. */
        if (debug_mask != 0)
            fprintf(stderr, "pqc_continuity: ignoring validity decrease for %s:%d "
                    "(cached=%ld, offered=%ld)\n",
                    host, port, (long)gc->entries[i].expiry, (long)expiry);
        goto done;
    }
    gc->entries[i].expiry = expiry;
    if (gc->enabled)
        pqc_gcache_persist(gc);

done:
    CRYPTO_THREAD_unlock(gc->lock);
    return ret;
}

/* Remove (host, port).  Acquires write lock.  Returns 1 if entry was found. */
static int pqc_cache_delete(pqc_gcache_t *gc, const char *host, int port)
{
    int i;
    if (gc == NULL) return 0;
    if (!CRYPTO_THREAD_write_lock(gc->lock)) return 0;
    i = pqc_gcache_find(gc, host, port);
    if (i >= 0) {
        gc->entries[i] = gc->entries[--gc->nentries];
        if (gc->enabled)
            pqc_gcache_persist(gc);
    }
    CRYPTO_THREAD_unlock(gc->lock);
    return (i >= 0);
}

/*
 * Load cache file into gc at init time.
 * Called under pqc_reg_lock write (single init path); no per-cache lock needed.
 */
static void pqc_gcache_load(pqc_gcache_t *gc)
{
    BIO *bio;
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long datalen;

    bio = BIO_new_file(gc->path, "r");
    if (bio == NULL) { ERR_clear_error(); return; }

    while (PEM_read_bio(bio, &name, &header, &data, &datalen) == 1) {
        if (strcmp(name, PQC_PEM_TYPE) == 0) {
            const unsigned char *p = data;
            PQC_CACHE_ENTRY *e = d2i_PQC_CACHE_ENTRY(NULL, &p, datalen);
            if (e != NULL) {
                int slen = e->host->length;
                int64_t port64, expiry64;
                if (slen > 0 && (size_t)slen < sizeof(gc->entries[0].host)
                        && ASN1_INTEGER_get_int64(&port64,   e->port)   == 1
                        && ASN1_INTEGER_get_int64(&expiry64, e->expiry) == 1) {
                    if (gc->nentries >= gc->cap && !pqc_gcache_grow(gc)) {
                        PQC_CACHE_ENTRY_free(e);
                        break;
                    }
                    memcpy(gc->entries[gc->nentries].host, e->host->data, slen);
                    gc->entries[gc->nentries].host[slen] = '\0';
                    gc->entries[gc->nentries].port   = (int)port64;
                    gc->entries[gc->nentries].expiry = (time_t)expiry64;
                    gc->nentries++;
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

    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    conn = (ssl != NULL && pqc_conn_ex_idx >= 0)
           ? SSL_get_ex_data(ssl, pqc_conn_ex_idx) : NULL;

    /* Run the previous verify callback first (if any). */
    if (conn != NULL && conn->prev_verify_cb != NULL)
        preverify_ok = conn->prev_verify_cb(preverify_ok, ctx);

    if (!preverify_ok) return 0;  /* already failing; don't pile on */
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
        if (conn->pctx != NULL && conn->pctx->debug_mask != 0)
            fprintf(stderr, "pqc_continuity: handshake done, verify_result=%ld (%s), "
                    "pending_op=%d for %s:%d\n",
                    vresult, (vresult == X509_V_OK ? "OK" : "FAIL"),
                    conn->op, conn->host, conn->port);

        if (vresult != X509_V_OK) {
            conn->op = PQC_PENDING_NONE;
            return;
        }

        if (conn->op == PQC_PENDING_UPDATE)
            pqc_cache_update(pqc_get_gcache(conn->pctx), conn->host, conn->port,
                             conn->expiry, conn->pctx ? conn->pctx->debug_mask : 0);
        else if (conn->op == PQC_PENDING_DELETE)
            pqc_cache_delete(pqc_get_gcache(conn->pctx), conn->host, conn->port);

        conn->op = PQC_PENDING_NONE;
    }
}

/* -------------------------------------------------------------------------
 * Extension wire helpers
 * ---------------------------------------------------------------------- */

/*
 * Allocate and fill a 6-byte CT extension buffer: uint16 scheme + uint32 validity.
 * Sets *out/*outlen on success; sets *al = SSL_AD_INTERNAL_ERROR and returns 0 on
 * alloc failure.  Returns 1 on success.
 */
static int pqc_encode_ct_ext(uint16_t scheme, uint32_t validity,
                              int *al,
                              const unsigned char **out, size_t *outlen)
{
    unsigned char *buf = OPENSSL_malloc(PQC_EXT_DATA_LEN);
    if (buf == NULL) { *al = SSL_AD_INTERNAL_ERROR; return 0; }
    buf[0] = (scheme >> 8) & 0xff;
    buf[1] =  scheme       & 0xff;
    buf[2] = (validity >> 24) & 0xff;
    buf[3] = (validity >> 16) & 0xff;
    buf[4] = (validity >>  8) & 0xff;
    buf[5] =  validity        & 0xff;
    *out = buf; *outlen = PQC_EXT_DATA_LEN;
    return 1;
}

/* Convenience: get the gcache for a pctx, or NULL if caching is disabled. */
static pqc_gcache_t *pqc_get_gcache(const pqc_ctx_t *pctx)
{
    if (pctx == NULL || pctx->cache_idx < 0) return NULL;
    return &pqc_caches[pctx->cache_idx];
}

/* -------------------------------------------------------------------------
 * Extension callbacks
 * ---------------------------------------------------------------------- */

/* --- CH add: client installs callbacks and restricts sigalgs on cache hit --- */
static int pqc_add_ch(SSL *s, pqc_ctx_t *pctx,
                      const unsigned char **out, size_t *outlen)
{
    char host[256];
    int port = 0;
    time_t cached_expiry = 0;
    pqc_conn_t *conn;
    pqc_gcache_t *gc = pqc_get_gcache(pctx);

    if (SSL_is_server(s)) return 0;

    /* Install info callback (chains CTX-level) and verify callback (mixed-chain). */
    SSL_set_info_callback(s, pqc_info_cb);
    conn = pqc_conn_get_or_create(s, pctx);
    if (conn != NULL) {
        conn->prev_verify_cb = SSL_get_verify_callback(s);
        SSL_set_verify(s, SSL_get_verify_mode(s), pqc_verify_cb);
    }

    /*
     * Cache hit: restrict to PQC-only sigalgs — core downgrade prevention.
     * Client won't offer traditional sigalgs to a previously-PQC server.
     */
    pqc_get_host_port(s, host, sizeof(host), &port);
    if (pqc_cache_lookup(gc, host, port, &cached_expiry)) {
        char sigalgs[512];
        SSL_CTX *sctx = SSL_get_SSL_CTX(s);
        if (pqc_build_sigalgs_list(sctx, sigalgs, sizeof(sigalgs))) {
            if (pctx->debug_mask != 0)
                fprintf(stderr, "pqc_continuity: cache hit %s:%d, restricting sigalgs to: %s\n",
                        host, port, sigalgs);
            SSL_set1_sigalgs_list(s, sigalgs);
        } else if (pctx->debug_mask != 0) {
            fprintf(stderr, "pqc_continuity: cache hit %s:%d but no PQC sigalgs in lookup cache\n",
                    host, port);
        }
    }

    *out = NULL; *outlen = 0;
    return 1;
}

/* --- CT add: server encodes scheme + validity (with debug fault injection) --- */
static int pqc_add_ct(SSL *s, pqc_ctx_t *pctx,
                      X509 *x, size_t chainidx,
                      int *al,
                      const unsigned char **out, size_t *outlen)
{
    EVP_PKEY *pkey;
    uint16_t scheme;

    /* Debug chainidx routing: normal path allows EE (chainidx 0) only.
     * CT_ONLY_INTERMEDIATE (A4b): send on chainidx 1, skip 0.
     * CT_ON_INTERMEDIATE (A4a): send on both 0 and 1. */
    if (pctx->debug_mask & PQC_DEBUG_CT_ONLY_INTERMEDIATE) {
        if (chainidx != 1) return 0;
        fprintf(stderr, "pqc_continuity: [debug] CT_ONLY_INTERMEDIATE — sending CT on chainidx 1 only\n");
    } else if (pctx->debug_mask & PQC_DEBUG_CT_ON_INTERMEDIATE) {
        if (chainidx > 1) return 0;
        if (chainidx == 1)
            fprintf(stderr, "pqc_continuity: [debug] CT_ON_INTERMEDIATE — also sending CT on chainidx 1\n");
    } else if (chainidx != 0) {
        return 0;
    }

    /* Server: only send CT if client included the CH extension (P1). */
    if (SSL_is_server(s)) {
        pqc_conn_t *conn = (pqc_conn_ex_idx >= 0)
                           ? SSL_get_ex_data(s, pqc_conn_ex_idx) : NULL;
        if (conn == NULL || !conn->client_sent_ch) {
            if (pctx->debug_mask != 0)
                fprintf(stderr, "pqc_continuity: server skipping CT — client did not send CH\n");
            return 0;
        }
    }

    pkey = (x != NULL) ? X509_get0_pubkey(x) : NULL;
    scheme = pqc_pkey_to_scheme(SSL_get_SSL_CTX(s), pkey);
    if (scheme == 0) {
        /* Traditional cert: empty extension signals presence only. */
        *out = NULL; *outlen = 0;
        return 1;
    }

    /* Debug fault injection — wrong/legacy/unknown scheme or malformed length. */
    if (pctx->debug_mask & PQC_DEBUG_WRONG_SCHEME) {
        uint16_t wrong;
        fprintf(stderr, "pqc_continuity: [debug] WRONG_SCHEME — sending mismatched scheme\n");
        if      (scheme == PQC_MLDSA44) wrong = PQC_MLDSA65;
        else if (scheme == PQC_MLDSA65) wrong = PQC_MLDSA87;
        else                             wrong = PQC_MLDSA44;
        return pqc_encode_ct_ext(wrong, pctx->validity_period, al, out, outlen);
    }
    if (pctx->debug_mask & PQC_DEBUG_LEGACY_SCHEME) {
        fprintf(stderr, "pqc_continuity: [debug] LEGACY_SCHEME — sending RSA scheme 0x0401\n");
        return pqc_encode_ct_ext(0x0401, pctx->validity_period, al, out, outlen);
    }
    if (pctx->debug_mask & PQC_DEBUG_MALFORMED_EXT) {
        unsigned char *buf;
        fprintf(stderr, "pqc_continuity: [debug] MALFORMED_EXT — sending 3-byte extension\n");
        buf = OPENSSL_malloc(3);
        if (buf == NULL) { *al = SSL_AD_INTERNAL_ERROR; return -1; }
        buf[0] = (scheme >> 8) & 0xff;
        buf[1] =  scheme       & 0xff;
        buf[2] = 0x42;
        *out = buf; *outlen = 3;
        return 1;
    }
    if (pctx->debug_mask & PQC_DEBUG_UNKNOWN_SCHEME) {
        fprintf(stderr, "pqc_continuity: [debug] UNKNOWN_SCHEME — sending scheme 0xFE42\n");
        return pqc_encode_ct_ext(0xFE42, pctx->validity_period, al, out, outlen);
    }

    /*
     * Normal path: PQC cert.  validity=0 instructs the client to clear its
     * cache; must send full extension (not empty) to distinguish from a
     * traditional-cert presence signal.
     */
    return pqc_encode_ct_ext(scheme, pctx->validity_period, al, out, outlen);
}

static int pqc_add_cb(SSL *s, unsigned int ext_type,
                       unsigned int context,
                       const unsigned char **out, size_t *outlen,
                       X509 *x, size_t chainidx,
                       int *al, void *add_arg)
{
    pqc_ctx_t *pctx = (pqc_ctx_t *)add_arg;
    if (pctx == NULL) return 0;

    if (context & SSL_EXT_CLIENT_HELLO)
        return pqc_add_ch(s, pctx, out, outlen);

    if (context & SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        if (!SSL_is_server(s)) return 0;
        *out = NULL; *outlen = 0;
        return 1;
    }

    if (context & SSL_EXT_TLS1_3_CERTIFICATE)
        return pqc_add_ct(s, pctx, x, chainidx, al, out, outlen);

    return 0;
}

static void pqc_free_cb(SSL *s, unsigned int ext_type,
                         unsigned int context,
                         const unsigned char *out, void *add_arg)
{
    if (context & SSL_EXT_TLS1_3_CERTIFICATE)
        OPENSSL_free((void *)out);
}

/* --- CT parse: client validates scheme vs cert, defers cache write --- */
static int pqc_parse_ct(SSL *s, pqc_ctx_t *pctx,
                         const unsigned char *in, size_t inlen,
                         X509 *x, size_t chainidx, int *al)
{
    char host[256];
    int port = 0;
    uint16_t scheme;
    uint32_t validity;
    pqc_conn_t *conn;
    pqc_gcache_t *gc = pqc_get_gcache(pctx);

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
         * Empty extension: traditional cert signals PQC support presence only.
         * If the client has a cache entry, this server previously had a PQC
         * cert — abort as a downgrade.
         */
        if (!SSL_is_server(s)) {
            time_t cached_expiry = 0;
            if (pqc_cache_lookup(gc, host, port, &cached_expiry)) {
                *al = SSL_AD_HANDSHAKE_FAILURE;
                return 0; /* downgrade detected */
            }
        }
        return 1;
    }

    if (inlen != PQC_EXT_DATA_LEN) { *al = SSL_AD_DECODE_ERROR; return 0; }

    scheme   = ((uint16_t)in[0] << 8) | (uint16_t)in[1];
    validity = ((uint32_t)in[2] << 24) | ((uint32_t)in[3] << 16)
             | ((uint32_t)in[4] <<  8) |  (uint32_t)in[5];

    /*
     * The scheme must exactly match the cert's public key.  Any deviation
     * (wrong PQC alg, legacy alg, unknown value) is treated as tampering.
     * No forward-compat carve-out: if the server sends this extension it must
     * be consistent with the cert it is presenting.
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
     * Do NOT write the cache here — this fires before ssl_verify_cert_chain().
     * Record the intent; pqc_info_cb() flushes it at SSL_CB_HANDSHAKE_DONE
     * after confirming X509_V_OK.
     */
    conn = pqc_conn_get_or_create(s, pctx);
    if (conn != NULL) {
        snprintf(conn->host, sizeof(conn->host), "%s", host);
        conn->port = port;
        if (validity == 0) {
            conn->op = PQC_PENDING_DELETE;
        } else {
            conn->op     = PQC_PENDING_UPDATE;
            conn->expiry = time(NULL) + (time_t)validity;
        }
        if (pctx->debug_mask != 0)
            fprintf(stderr, "pqc_continuity: CT parse_cb deferring cache %s for %s:%d\n",
                    validity == 0 ? "delete" : "update", host, port);
    }

    return 1;
}

static int pqc_parse_cb(SSL *s, unsigned int ext_type,
                          unsigned int context,
                          const unsigned char *in, size_t inlen,
                          X509 *x, size_t chainidx,
                          int *al, void *parse_arg)
{
    pqc_ctx_t *pctx = (pqc_ctx_t *)parse_arg;
    pqc_conn_t *conn;

    if (pctx == NULL) return 1;

    if (context & SSL_EXT_CLIENT_HELLO) {
        /* Server notes that client supports the extension. */
        if (SSL_is_server(s)) {
            conn = pqc_conn_get_or_create(s, pctx);
            if (conn != NULL)
                conn->client_sent_ch = 1;
        }
        return 1;
    }

    if (context & SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        if (!SSL_is_server(s)) {
            conn = pqc_conn_get_or_create(s, pctx);
            if (conn != NULL)
                conn->server_sent_cr = 1;
        }
        return 1;
    }

    if (context & SSL_EXT_TLS1_3_CERTIFICATE)
        return pqc_parse_ct(s, pctx, in, inlen, x, chainidx, al);

    return 1;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/*
 * Load [pqc_continuity] from $OPENSSL_CONF.
 * Fills pctx->validity_period, pctx->debug_mask, and cache_path/cache_enabled
 * into a temporary struct so the caller can do registry lookup.
 *
 * Returns  1  if section found and not disabled.
 * Returns  0  if section absent (silently disabled).
 * Returns -1  if Enable = no (explicitly disabled).
 *
 * cache_path_out must be at least 512 bytes; cache_enabled_out is set to 1
 * if CachePath was present.
 */
static int pqc_ctx_load_config(pqc_ctx_t *pctx,
                                char *cache_path_out, int *cache_enabled_out)
{
    CONF *conf = NULL;
    long eline = 0;
    int section_found = 0;
    const char *conffile = getenv("OPENSSL_CONF");
    if (conffile == NULL) conffile = getenv("SSLEAY_CONF");
    if (conffile == NULL) return 0;

    conf = NCONF_new(NULL);
    if (conf == NULL) return 0;
    if (NCONF_load(conf, conffile, &eline) <= 0) {
        NCONF_free(conf); ERR_clear_error(); return 0;
    }

    {
        char *val;

        val = NCONF_get_string(conf, "pqc_continuity", "Enable");
        if (val != NULL) {
            section_found = 1;
            if (strcasecmp(val, "no") == 0) {
                NCONF_free(conf); return -1;
            }
        } else { ERR_clear_error(); }

        val = NCONF_get_string(conf, "pqc_continuity", "ValidityPeriod");
        if (val != NULL) {
            section_found = 1;
            pctx->validity_period = (uint32_t)strtoul(val, NULL, 10);
        } else { ERR_clear_error(); }

        val = NCONF_get_string(conf, "pqc_continuity", "CachePath");
        if (val != NULL) {
            section_found = 1;
            snprintf(cache_path_out, 512, "%s", val);
            *cache_enabled_out = 1;
        } else { ERR_clear_error(); }

        val = NCONF_get_string(conf, "pqc_continuity", "Debug");
        if (val != NULL) {
            section_found = 1;
            pctx->debug_mask = (uint32_t)strtoul(val, NULL, 16);
            if (pctx->debug_mask != 0)
                fprintf(stderr, "pqc_continuity: debug_mask=0x%02x (fault injection active)\n",
                        pctx->debug_mask);
        } else { ERR_clear_error(); }
    }

    NCONF_free(conf);
    ERR_clear_error();
    return section_found ? 1 : 0;
}

/*
 * Look up or create a pqc_gcache_t for the given path.
 * Must be called with pqc_reg_lock write-held.
 * Returns the index into pqc_caches[], or -1 on failure.
 */
static int pqc_gcache_get_or_create(const char *path)
{
    int i;

    /* Search existing entries. */
    for (i = 0; i < pqc_ncaches; i++) {
        if (strcmp(pqc_caches[i].path, path) == 0)
            return i;
    }

    /* New path — allocate a slot. */
    if (pqc_ncaches >= PQC_MAX_CACHES) {
        fprintf(stderr, "pqc_continuity: too many cache paths (max %d), "
                "disabling cache for %s\n", PQC_MAX_CACHES, path);
        return -1;
    }

    i = pqc_ncaches;
    snprintf(pqc_caches[i].path, sizeof(pqc_caches[i].path), "%s", path);
    pqc_caches[i].enabled = 1;
    pqc_caches[i].lock = CRYPTO_THREAD_lock_new();
    if (pqc_caches[i].lock == NULL) return -1;
    pqc_gcache_load(&pqc_caches[i]);
    pqc_ncaches++;
    return i;
}

int pqc_cont_init(SSL_CTX *ctx)
{
    pqc_ctx_t *pctx;
    char cache_path[512] = "";
    int cache_enabled = 0;
    int cfg;
    unsigned int contexts;

    /* One-time inits: SSL ex_data slot and registry lock. */
    if (!RUN_ONCE(&pqc_ex_idx_once, pqc_ex_idx_init)) return 0;
    if (!RUN_ONCE(&pqc_reg_once,    pqc_reg_init))    return 0;

    pctx = OPENSSL_zalloc(sizeof(*pctx));
    if (pctx == NULL) return 0;
    pctx->cache_idx = -1;

    cfg = pqc_ctx_load_config(pctx, cache_path, &cache_enabled);
    if (cfg <= 0) {
        /* 0 = no section (silently disabled), -1 = explicitly disabled */
        OPENSSL_free(pctx);
        return 1;
    }

    if (cache_enabled) {
        /* Registry lookup/insert under write lock. */
        if (CRYPTO_THREAD_write_lock(pqc_reg_lock)) {
            pctx->cache_idx = pqc_gcache_get_or_create(cache_path);
            CRYPTO_THREAD_unlock(pqc_reg_lock);
        }
        /* cache_idx == -1 means caching disabled for this ctx; extension still works. */
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
