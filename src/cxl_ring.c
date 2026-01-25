/* TDX shared-memory transport for Redis (no RESP parsing).
 *
 * This replaces the older "CXLSHM1" ring layout with the lightweight
 * double-queue layout used in /home/ubuntu/test-tdx:
 *   - q21: client (VM2) -> server (VM1) requests
 *   - q12: server (VM1) -> client (VM2) responses
 *
 * Message framing per slot (4KiB):
 *   u16 msg_len (bytes after this prefix)
 *   16B header: cid,u16 type,u16 flags,u32 len,u32 reserved
 *   payload (len bytes)
 *
 * Payload protocol (binary GET/SET):
 *   Request:  u8 op (1=GET,2=SET), u8 key_len, u16 val_len (LE), key, val
 *   Response: u8 status (0=OK,1=MISS,2=ERR), u16 val_len (LE), u8 reserved, val
 */

#include "server.h"
#include "sds.h"

#include "../../tdx_shm/tdx_shm_transport.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MSG_DATA 1
#define MSG_CLOSE 2

#define DEFAULT_MAP_SIZE (1024 * 1024 * 1024ULL) /* 1GB */
#define DEFAULT_RING_COUNT 4
#define MAX_RINGS 8

#define RING_SLOT_HDR_SIZE 16U
#define RING_MAX_PAYLOAD ((uint32_t)TDX_SHM_MSG_MAX - RING_SLOT_HDR_SIZE)

/* Shared-memory security table (cxl_sec_mgr). */
#define CXL_SEC_TABLE_OFF 512
#define CXL_SEC_MAGIC "CXLSEC1\0"
#define CXL_SEC_VERSION 1
#define CXL_SEC_MAX_ENTRIES (MAX_RINGS * 2)
#define CXL_SEC_MAX_PRINCIPALS 16

#define SEC_PROTO_MAGIC 0x43534543u /* 'CSEC' */
#define SEC_PROTO_VERSION 1
#define SEC_REQ_ACCESS 1

#define SEC_STATUS_OK 0

/* ring_slot_hdr.flags */
#define RING_FLAG_SECURE 0x0001u
#define RING_FLAG_RESP   0x0002u

#define SEC_DIR_REQ 1u  /* client->server */
#define SEC_DIR_RESP 2u /* server->client */

typedef struct {
    uint64_t start_off;
    uint64_t end_off;
    unsigned char key[crypto_stream_chacha20_ietf_KEYBYTES];
    uint32_t principal_count;
    uint32_t reserved;
    uint64_t principals[CXL_SEC_MAX_PRINCIPALS];
} CxlSecEntry;

typedef struct {
    char magic[8];
    uint32_t version;
    uint32_t entry_count;
    CxlSecEntry entries[CXL_SEC_MAX_ENTRIES];
} CxlSecTable;

struct sec_req {
    uint32_t magic_be;
    uint16_t version_be;
    uint16_t type_be;
    uint64_t principal_be;
    uint64_t offset_be;
    uint32_t length_be;
    uint32_t reserved_be;
};

struct sec_resp {
    uint32_t magic_be;
    uint16_t version_be;
    uint16_t status_be;
    uint32_t reserved_be;
};

enum {
    CXL_OP_GET = 1,
    CXL_OP_SET = 2
};
enum {
    CXL_STATUS_OK = 0,
    CXL_STATUS_MISS = 1,
    CXL_STATUS_ERR = 2
};

struct ring_slot_hdr {
    uint32_t cid;
    uint16_t type;
    uint16_t flags;
    uint32_t len;
    uint32_t reserved;
};

typedef struct {
    int enabled;
    int fd;
    size_t map_size;
    size_t map_offset;
    size_t file_size;
    unsigned char *mm;

    uint64_t shm_delay_ns;
    uint64_t shm_pause_iters_per_ns_x1024;

    int ring_count;
    size_t region_size;
    size_t region_base;

    struct tdx_shm_queue_view req[MAX_RINGS];  /* q21: client -> server */
    struct tdx_shm_queue_view resp[MAX_RINGS]; /* q12: server -> client */

    long long timer_id;
    unsigned long long req_seen[MAX_RINGS];

    int secure_enabled;
    int crypto_enabled; /* manager-less crypto mode (vm key + common key) */
    uint64_t sec_node_id;
    unsigned sec_timeout_ms;
    char sec_mgr[256];
    unsigned char sec_key[MAX_RINGS][crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    int sec_key_ok[MAX_RINGS];
    atomic_uint_fast64_t sec_nonce_ctr_resp[MAX_RINGS];

    /* Crypto mode: per-node private staging area (encrypted with VM key). */
    unsigned char crypto_vm_key[crypto_stream_chacha20_ietf_KEYBYTES];
    unsigned char crypto_common_key[crypto_stream_chacha20_ietf_KEYBYTES];
    size_t crypto_priv_region_base;
    size_t crypto_priv_region_size;
    unsigned char *crypto_priv; /* this node's private region (within shared mmap) */
    atomic_uint_fast64_t crypto_priv_nonce_ctr[MAX_RINGS];
} CxlRingCtx;

static CxlRingCtx g_ctx = {0};
static int cxlRingCron(aeEventLoop *eventLoop, long long id, void *clientData);

typedef struct RespConn {
    uint32_t cid;
    int ring_idx;
    client *c;
    sds out;
    size_t out_off;
    int closing;
    int in_pending;
    struct RespConn *pending_prev;
    struct RespConn *pending_next;
} RespConn;

static RespConn **g_resp_map = NULL;
static size_t g_resp_cap = 0;
static RespConn *g_resp_pending_head = NULL;
static connection g_resp_dummy_conn;

static int queue_send(struct tdx_shm_queue_view *tx, uint32_t cid, uint16_t type, uint16_t flags, const unsigned char *payload, uint32_t len);

static inline size_t align_up(size_t x, size_t a) {
    return (x + a - 1) / a * a;
}

static inline uint64_t nowns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void cxl_shm_delay_calibrate(void) {
    if (g_ctx.shm_pause_iters_per_ns_x1024) return;
    const uint64_t iters = 5000000ULL;
    uint64_t start = nowns();
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
    uint64_t dt = nowns() - start;
    if (dt == 0) dt = 1;
    g_ctx.shm_pause_iters_per_ns_x1024 = (iters * 1024ULL) / dt;
    if (g_ctx.shm_pause_iters_per_ns_x1024 == 0) g_ctx.shm_pause_iters_per_ns_x1024 = 1;
}

static inline void cxl_shm_delay(void) {
    uint64_t ns = g_ctx.shm_delay_ns;
    if (!ns) return;
    if (!g_ctx.shm_pause_iters_per_ns_x1024) cxl_shm_delay_calibrate();
    uint64_t iters = (ns * g_ctx.shm_pause_iters_per_ns_x1024 + 1023ULL) / 1024ULL;
    if (iters == 0) iters = 1;
    for (uint64_t i = 0; i < iters; i++) {
        __asm__ __volatile__("pause");
    }
}

static int parse_size(const char *arg, size_t *out) {
    if (!arg || !out) return C_ERR;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(arg, &end, 0);
    if (errno != 0) return C_ERR;

    unsigned long long multiplier = 1ULL;
    if (end && *end != '\0') {
        if (end[1] != '\0') return C_ERR;
        switch (*end) {
            case 'K':
            case 'k':
                multiplier = 1024ULL;
                break;
            case 'M':
            case 'm':
                multiplier = 1024ULL * 1024ULL;
                break;
            case 'G':
            case 'g':
                multiplier = 1024ULL * 1024ULL * 1024ULL;
                break;
            default:
                return C_ERR;
        }
    }
    if (multiplier != 0ULL && value > (ULLONG_MAX / multiplier)) return C_ERR;
    unsigned long long bytes = value * multiplier;
    if (bytes > (unsigned long long)SIZE_MAX) return C_ERR;
    *out = (size_t)bytes;
    return C_OK;
}

static size_t env_size(const char *key, size_t def) {
    const char *v = getenv(key);
    if (!v || !v[0]) return def;
    size_t out = 0;
    if (parse_size(v, &out) != C_OK) return def;
    return out;
}

static int env_enabled(const char *key) {
    const char *v = getenv(key);
    if (!v || !v[0]) return 0;
    if (!strcmp(v, "0") || !strcasecmp(v, "false") || !strcasecmp(v, "no")) return 0;
    return 1;
}

static int parse_key_hex(const char *hex, unsigned char *out_key, size_t out_len) {
    if (!hex || !hex[0] || !out_key || out_len == 0) return C_ERR;
    size_t bin_len = 0;
    if (sodium_hex2bin(out_key, out_len, hex, strlen(hex), NULL, &bin_len, NULL) != 0) return C_ERR;
    if (bin_len != out_len) return C_ERR;
    return C_OK;
}

static int parse_hostport(const char *s, char **host_out, char **port_out) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s || *(colon + 1) == '\0') return -1;
    size_t host_len = (size_t)(colon - s);
    char *host = (char *)zcalloc(host_len + 1);
    char *port = zstrdup(colon + 1);
    if (!host || !port) {
        zfree(host);
        zfree(port);
        return -1;
    }
    memcpy(host, s, host_len);
    host[host_len] = '\0';
    *host_out = host;
    *port_out = port;
    return 0;
}

static ssize_t read_full(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (unsigned char *)buf + off, n - off);
        if (r == 0) return (ssize_t)off;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return (ssize_t)off;
}

static int write_full(int fd, const void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const unsigned char *)buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int socket_connect(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        serverLog(LL_WARNING, "cxl_sec: getaddrinfo(connect %s:%s): %s", host, port, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static void sleep_ms(unsigned ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000U;
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

static int sec_table_ready(const CxlSecTable *t) {
    if (!t) return 0;
    if (memcmp(t->magic, CXL_SEC_MAGIC, 8) != 0) return 0;
    if (t->version != CXL_SEC_VERSION) return 0;
    if (t->entry_count == 0 || t->entry_count > CXL_SEC_MAX_ENTRIES) return 0;
    return 1;
}

static int sec_table_find(const CxlSecTable *t, uint64_t off, uint64_t len, uint32_t *idx_out) {
    if (!t || !idx_out || !sec_table_ready(t)) return -1;
    if (len == 0) return -1;
    uint64_t end = off + len;
    if (end < off) return -1;
    uint32_t n = t->entry_count;
    if (n > CXL_SEC_MAX_ENTRIES) n = CXL_SEC_MAX_ENTRIES;
    for (uint32_t i = 0; i < n; i++) {
        const CxlSecEntry *e = &t->entries[i];
        if (off >= e->start_off && end <= e->end_off) {
            *idx_out = i;
            return 0;
        }
    }
    return -1;
}

static int sec_entry_has_principal(const CxlSecEntry *e, uint64_t principal) {
    if (!e) return 0;
    uint32_t n = e->principal_count;
    if (n > CXL_SEC_MAX_PRINCIPALS) n = CXL_SEC_MAX_PRINCIPALS;
    for (uint32_t i = 0; i < n; i++) {
        if (e->principals[i] == principal) return 1;
    }
    return 0;
}

static int sec_mgr_request_access(const char *mgr, uint64_t principal, uint64_t off, uint32_t len) {
    char *host = NULL, *port = NULL;
    if (parse_hostport(mgr, &host, &port) != 0) return -1;

    int fd = socket_connect(host, port);
    if (fd < 0) {
        zfree(host);
        zfree(port);
        return -1;
    }

    struct sec_req req;
    memset(&req, 0, sizeof(req));
    req.magic_be = htonl(SEC_PROTO_MAGIC);
    req.version_be = htons(SEC_PROTO_VERSION);
    req.type_be = htons(SEC_REQ_ACCESS);
    req.principal_be = htobe64(principal);
    req.offset_be = htobe64(off);
    req.length_be = htonl(len);

    int rc = -1;
    if (write_full(fd, &req, sizeof(req)) != 0) goto out;
    struct sec_resp resp;
    ssize_t r = read_full(fd, &resp, sizeof(resp));
    if (r != (ssize_t)sizeof(resp)) goto out;

    uint32_t magic = ntohl(resp.magic_be);
    uint16_t ver = ntohs(resp.version_be);
    uint16_t status = ntohs(resp.status_be);
    if (magic != SEC_PROTO_MAGIC || ver != SEC_PROTO_VERSION) goto out;
    if (status != SEC_STATUS_OK) goto out;
    rc = 0;
out:
    close(fd);
    zfree(host);
    zfree(port);
    return rc;
}

static int crypto_priv_init(void) {
    if (!g_ctx.crypto_enabled) return C_OK;
    if (!g_ctx.mm || g_ctx.mm == MAP_FAILED) return C_ERR;
    if (g_ctx.ring_count < 1 || g_ctx.ring_count > MAX_RINGS) return C_ERR;
    if (g_ctx.sec_node_id == 0) {
        serverLog(LL_WARNING, "cxl_crypto: requires CXL_SEC_NODE_ID");
        return C_ERR;
    }

    const size_t slot_stride = (size_t)TDX_SHM_SLOT_SIZE;
    const size_t need_bytes = align_up((size_t)g_ctx.ring_count * slot_stride, 4096U);

    const size_t def_base = align_up(g_ctx.region_base + (size_t)g_ctx.ring_count * g_ctx.region_size, 4096U);
    const size_t base = env_size("CXL_CRYPTO_PRIV_REGION_BASE", def_base);
    const size_t per_node = env_size("CXL_CRYPTO_PRIV_REGION_SIZE", need_bytes);
    if ((base % 4096) != 0 || (per_node % 4096) != 0) {
        serverLog(LL_WARNING,
                  "cxl_crypto: CXL_CRYPTO_PRIV_REGION_BASE/SIZE must be 4K-aligned (base=%zu size=%zu)",
                  base, per_node);
        return C_ERR;
    }
    if (per_node < need_bytes) {
        serverLog(LL_WARNING,
                  "cxl_crypto: CXL_CRYPTO_PRIV_REGION_SIZE too small (need >= %zu, got %zu)",
                  need_bytes, per_node);
        return C_ERR;
    }

    uint64_t idx = g_ctx.sec_node_id - 1ULL;
    uint64_t off64 = (uint64_t)base + idx * (uint64_t)per_node;
    if (off64 > (uint64_t)g_ctx.map_size || (uint64_t)per_node > (uint64_t)g_ctx.map_size - off64) {
        serverLog(LL_WARNING,
                  "cxl_crypto: private region out of range (map_size=%zu base=%zu node=%llu per_node=%zu)",
                  g_ctx.map_size, base, (unsigned long long)g_ctx.sec_node_id, per_node);
        return C_ERR;
    }

    g_ctx.crypto_priv_region_base = base;
    g_ctx.crypto_priv_region_size = per_node;
    g_ctx.crypto_priv = g_ctx.mm + (size_t)off64;
    memset(g_ctx.crypto_priv, 0, per_node);
    for (int i = 0; i < g_ctx.ring_count; i++) {
        atomic_store_explicit(&g_ctx.crypto_priv_nonce_ctr[i], 0, memory_order_relaxed);
    }

    serverLog(LL_NOTICE,
              "cxl_crypto: private region ready (node_id=%llu base=%zu per_node=%zu need=%zu)",
              (unsigned long long)g_ctx.sec_node_id, base, per_node, need_bytes);
    return C_OK;
}

static int crypto_priv_encrypt_then_decrypt(uint32_t ring_idx,
                                            unsigned dir,
                                            const unsigned char *payload,
                                            uint32_t payload_len,
                                            unsigned char *out,
                                            uint32_t out_cap,
                                            uint32_t *out_len) {
    if (!out || !out_len || !payload) return C_ERR;
    if (!g_ctx.crypto_enabled || !g_ctx.crypto_priv) return C_ERR;
    if (ring_idx >= (uint32_t)g_ctx.ring_count || ring_idx >= MAX_RINGS) return C_ERR;
    if (payload_len > out_cap) return C_ERR;

    const size_t slot_stride = (size_t)TDX_SHM_SLOT_SIZE;
    const uint32_t nonce_bytes = crypto_stream_chacha20_ietf_NONCEBYTES;
    if ((size_t)payload_len + (size_t)nonce_bytes > slot_stride) return C_ERR;

    unsigned char *slot = g_ctx.crypto_priv + (size_t)ring_idx * slot_stride;
    unsigned char *nonce = slot;
    unsigned char *cipher = slot + nonce_bytes;

    cxl_shm_delay();
    memset(nonce, 0, nonce_bytes);
    nonce[0] = (unsigned char)(dir & 0xffu);
    nonce[1] = (unsigned char)(ring_idx & 0xffu);
    uint64_t ctr = atomic_fetch_add_explicit(&g_ctx.crypto_priv_nonce_ctr[ring_idx], 1, memory_order_relaxed);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (unsigned char)((ctr >> (8 * i)) & 0xffu);
    }

    memcpy(cipher, payload, payload_len);
    crypto_stream_chacha20_ietf_xor(cipher,
                                    cipher,
                                    (unsigned long long)payload_len,
                                    nonce,
                                    g_ctx.crypto_vm_key);

    cxl_shm_delay();
    crypto_stream_chacha20_ietf_xor(out,
                                    cipher,
                                    (unsigned long long)payload_len,
                                    nonce,
                                    g_ctx.crypto_vm_key);
    *out_len = payload_len;
    return C_OK;
}

static int cxl_sec_init(void) {
    g_ctx.secure_enabled = env_enabled("CXL_SEC_ENABLE");
    if (!g_ctx.secure_enabled) return C_OK;

    if (sodium_init() < 0) {
        serverLog(LL_WARNING, "cxl_sec: sodium_init failed");
        return C_ERR;
    }

    const char *id_env = getenv("CXL_SEC_NODE_ID");
    if (!id_env || !id_env[0]) {
        serverLog(LL_WARNING, "cxl_sec: CXL_SEC_ENABLE=1 requires CXL_SEC_NODE_ID");
        return C_ERR;
    }
    g_ctx.sec_node_id = strtoull(id_env, NULL, 0);
    if (g_ctx.sec_node_id == 0) {
        serverLog(LL_WARNING, "cxl_sec: invalid CXL_SEC_NODE_ID=%s", id_env);
        return C_ERR;
    }

    g_ctx.sec_timeout_ms = 10000;
    const char *to_env = getenv("CXL_SEC_TIMEOUT_MS");
    if (to_env && to_env[0]) {
        g_ctx.sec_timeout_ms = (unsigned)strtoul(to_env, NULL, 0);
    }

    const char *key_hex = getenv("CXL_SEC_KEY_HEX");
    if (key_hex && key_hex[0]) {
        /* Crypto mode: no manager, pre-shared keys (VM key + common key). */
        const char *common_hex = getenv("CXL_SEC_COMMON_KEY_HEX");
        if (!common_hex || !common_hex[0]) {
            serverLog(LL_WARNING, "cxl_crypto: CXL_SEC_KEY_HEX requires CXL_SEC_COMMON_KEY_HEX");
            return C_ERR;
        }
        if (parse_key_hex(key_hex, g_ctx.crypto_vm_key, sizeof(g_ctx.crypto_vm_key)) != C_OK) {
            serverLog(LL_WARNING, "cxl_crypto: invalid CXL_SEC_KEY_HEX (expected %d bytes hex)",
                      (int)sizeof(g_ctx.crypto_vm_key));
            return C_ERR;
        }
        if (parse_key_hex(common_hex, g_ctx.crypto_common_key, sizeof(g_ctx.crypto_common_key)) != C_OK) {
            serverLog(LL_WARNING, "cxl_crypto: invalid CXL_SEC_COMMON_KEY_HEX (expected %d bytes hex)",
                      (int)sizeof(g_ctx.crypto_common_key));
            return C_ERR;
        }
        g_ctx.crypto_enabled = 1;
        memset(g_ctx.sec_mgr, 0, sizeof(g_ctx.sec_mgr));
        memset(g_ctx.sec_key_ok, 0, sizeof(g_ctx.sec_key_ok));
        for (int i = 0; i < g_ctx.ring_count && i < MAX_RINGS; i++) {
            memcpy(g_ctx.sec_key[i], g_ctx.crypto_common_key, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
            g_ctx.sec_key_ok[i] = 1;
            atomic_store_explicit(&g_ctx.sec_nonce_ctr_resp[i], 0, memory_order_relaxed);
        }
        if (crypto_priv_init() != C_OK) return C_ERR;
        serverLog(LL_NOTICE, "cxl_crypto: enabled (node_id=%llu)", (unsigned long long)g_ctx.sec_node_id);
        return C_OK;
    }

    /* Secure mode: manager-backed ACL table + per-ring key. */
    const char *mgr = getenv("CXL_SEC_MGR");
    if (!mgr || !mgr[0]) {
        serverLog(LL_WARNING, "cxl_sec: CXL_SEC_ENABLE=1 requires either CXL_SEC_KEY_HEX=<hex> or CXL_SEC_MGR=ip:port");
        return C_ERR;
    }
    snprintf(g_ctx.sec_mgr, sizeof(g_ctx.sec_mgr), "%s", mgr);

    if (g_ctx.region_base < 4096) {
        serverLog(LL_WARNING, "cxl_sec: secure mode requires CXL_RING_REGION_BASE >= 4096");
        return C_ERR;
    }
    if (g_ctx.map_size < CXL_SEC_TABLE_OFF + sizeof(CxlSecTable)) {
        serverLog(LL_WARNING, "cxl_sec: mapping too small for CXLSEC table");
        return C_ERR;
    }

    const CxlSecTable *t = (const CxlSecTable *)(g_ctx.mm + CXL_SEC_TABLE_OFF);
    unsigned waited = 0;
    while (1) {
        if (sec_table_ready(t)) break;
        if (waited >= g_ctx.sec_timeout_ms) break;
        sleep_ms(10);
        waited += 10;
    }
    if (!sec_table_ready(t)) {
        serverLog(LL_WARNING, "cxl_sec: timeout waiting for CXLSEC table");
        return C_ERR;
    }

    for (int i = 0; i < g_ctx.ring_count; i++) {
        uint64_t off = (uint64_t)g_ctx.region_base + (uint64_t)i * (uint64_t)g_ctx.region_size;
        uint32_t idx = 0;
        if (sec_table_find(t, off, 1, &idx) != 0) {
            serverLog(LL_WARNING, "cxl_sec: no table entry for ring=%d off=%llu", i, (unsigned long long)off);
            return C_ERR;
        }

        unsigned waited2 = 0;
        while (1) {
            if (sec_entry_has_principal(&t->entries[idx], g_ctx.sec_node_id)) break;
            (void)sec_mgr_request_access(g_ctx.sec_mgr, g_ctx.sec_node_id, off, 1);
            if (waited2 >= g_ctx.sec_timeout_ms) break;
            sleep_ms(10);
            waited2 += 10;
        }
        if (!sec_entry_has_principal(&t->entries[idx], g_ctx.sec_node_id)) {
            serverLog(LL_WARNING, "cxl_sec: principal %llu not granted for ring=%d",
                      (unsigned long long)g_ctx.sec_node_id, i);
            return C_ERR;
        }

        memcpy(g_ctx.sec_key[i], t->entries[idx].key, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        g_ctx.sec_key_ok[i] = 1;
        atomic_store_explicit(&g_ctx.sec_nonce_ctr_resp[i], 0, memory_order_relaxed);
    }

    serverLog(LL_NOTICE, "cxl_sec: enabled (node_id=%llu mgr=%s)", (unsigned long long)g_ctx.sec_node_id, g_ctx.sec_mgr);
    return C_OK;
}

static int sec_encrypt(uint32_t ring_idx,
                       uint32_t cid,
                       uint16_t type,
                       uint16_t flags,
                       const unsigned char *payload,
                       uint32_t payload_len,
                       unsigned dir,
                       unsigned char *out,
                       uint32_t out_cap,
                       uint32_t *out_len) {
    if (!out || !out_len || !payload) return C_ERR;
    if (!g_ctx.secure_enabled) return C_ERR;
    if (ring_idx >= (uint32_t)g_ctx.ring_count || ring_idx >= MAX_RINGS) return C_ERR;
    if (!g_ctx.sec_key_ok[ring_idx]) return C_ERR;

    const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (payload_len > RING_MAX_PAYLOAD) return C_ERR;
    if (payload_len > RING_MAX_PAYLOAD - nonce_bytes - tag_bytes) return C_ERR;

    uint32_t clen_total = nonce_bytes + payload_len + tag_bytes;
    if (clen_total > out_cap) return C_ERR;

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = clen_total;
    hdr.reserved = 0;

    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memset(nonce, 0, sizeof(nonce));
    nonce[0] = (unsigned char)(dir & 0xffu);
    nonce[1] = (unsigned char)(ring_idx & 0xffu);
    uint64_t ctr = atomic_fetch_add_explicit(&g_ctx.sec_nonce_ctr_resp[ring_idx], 1, memory_order_relaxed);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (unsigned char)((ctr >> (8 * i)) & 0xffu);
    }

    memcpy(out, nonce, nonce_bytes);
    unsigned long long cbytes = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(out + nonce_bytes,
                                                  &cbytes,
                                                  payload,
                                                  (unsigned long long)payload_len,
                                                  (const unsigned char *)&hdr,
                                                  (unsigned long long)sizeof(hdr),
                                                  NULL,
                                                  nonce,
                                                  g_ctx.sec_key[ring_idx]) != 0) {
        return C_ERR;
    }
    if (cbytes != (unsigned long long)(payload_len + tag_bytes)) return C_ERR;
    *out_len = (uint32_t)(nonce_bytes + (uint32_t)cbytes);
    return C_OK;
}

static int sec_decrypt(uint32_t ring_idx,
                       uint32_t cid,
                       uint16_t type,
                       uint16_t flags,
                       const unsigned char *payload,
                       uint32_t payload_len,
                       unsigned char *out,
                       uint32_t out_cap,
                       uint32_t *out_len) {
    if (!out || !out_len || !payload) return C_ERR;
    if (!g_ctx.secure_enabled) return C_ERR;
    if (ring_idx >= (uint32_t)g_ctx.ring_count || ring_idx >= MAX_RINGS) return C_ERR;
    if (!g_ctx.sec_key_ok[ring_idx]) return C_ERR;

    const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (payload_len < nonce_bytes + tag_bytes) return C_ERR;
    uint32_t clen = payload_len - nonce_bytes;
    if (clen < tag_bytes) return C_ERR;
    uint32_t pmax = clen - tag_bytes;
    if (pmax > out_cap) return C_ERR;

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = payload_len;
    hdr.reserved = 0;

    const unsigned char *nonce = payload;
    const unsigned char *cipher = payload + nonce_bytes;
    unsigned long long pbytes = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(out,
                                                  &pbytes,
                                                  NULL,
                                                  cipher,
                                                  (unsigned long long)clen,
                                                  (const unsigned char *)&hdr,
                                                  (unsigned long long)sizeof(hdr),
                                                  nonce,
                                                  g_ctx.sec_key[ring_idx]) != 0) {
        return C_ERR;
    }
    if (pbytes > (unsigned long long)out_cap) return C_ERR;
    *out_len = (uint32_t)pbytes;
    return C_OK;
}

static uint32_t ring_next(uint32_t v, uint32_t cap) {
    return (v + 1U) % cap;
}

static void resp_pending_add(RespConn *rc) {
    if (!rc || rc->in_pending) return;
    rc->in_pending = 1;
    rc->pending_prev = NULL;
    rc->pending_next = g_resp_pending_head;
    if (g_resp_pending_head) g_resp_pending_head->pending_prev = rc;
    g_resp_pending_head = rc;
}

static void resp_pending_remove(RespConn *rc) {
    if (!rc || !rc->in_pending) return;
    if (rc->pending_prev) rc->pending_prev->pending_next = rc->pending_next;
    else g_resp_pending_head = rc->pending_next;
    if (rc->pending_next) rc->pending_next->pending_prev = rc->pending_prev;
    rc->pending_prev = NULL;
    rc->pending_next = NULL;
    rc->in_pending = 0;
}

static int resp_ensure_slot(uint32_t cid) {
    if (cid < g_resp_cap) return C_OK;
    size_t ncap = g_resp_cap ? g_resp_cap : 1024;
    while (cid >= ncap) ncap *= 2;
    RespConn **nm = zrealloc(g_resp_map, ncap * sizeof(nm[0]));
    if (!nm) return C_ERR;
    for (size_t i = g_resp_cap; i < ncap; i++) nm[i] = NULL;
    g_resp_map = nm;
    g_resp_cap = ncap;
    return C_OK;
}

static void resp_conn_free(RespConn *rc) {
    if (!rc) return;
    resp_pending_remove(rc);
    if (rc->cid < g_resp_cap) g_resp_map[rc->cid] = NULL;
    if (rc->out) sdsfree(rc->out);
    if (rc->c) freeClient(rc->c);
    zfree(rc);
}

static RespConn *resp_get_or_create(uint32_t cid, int ring_idx) {
    if (resp_ensure_slot(cid) != C_OK) return NULL;
    RespConn *rc = g_resp_map[cid];
    if (rc) {
        if (ring_idx >= 0) rc->ring_idx = ring_idx;
        return rc;
    }
    rc = zcalloc(sizeof(*rc));
    if (!rc) return NULL;
    rc->cid = cid;
    rc->ring_idx = ring_idx;
    rc->c = createClient(NULL);
    if (!rc->c) {
        zfree(rc);
        return NULL;
    }
    /* Allow replies without an underlying socket connection. */
    rc->c->flags |= CLIENT_MODULE | CLIENT_NO_EVICT;
    rc->out = NULL;
    rc->out_off = 0;
    rc->closing = 0;
    g_resp_map[cid] = rc;
    return rc;
}

static void resp_drain_client_output(RespConn *rc) {
    if (!rc || !rc->c) return;
    client *c = rc->c;

    if (c->bufpos) {
        if (!rc->out) rc->out = sdsempty();
        rc->out = sdscatlen(rc->out, c->buf, c->bufpos);
        c->bufpos = 0;
    }
    while (listLength(c->reply)) {
        listNode *ln = listFirst(c->reply);
        clientReplyBlock *blk = ln ? listNodeValue(ln) : NULL;
        if (blk && blk->used) {
            if (!rc->out) rc->out = sdsempty();
            rc->out = sdscatlen(rc->out, blk->buf, blk->used);
        }
        if (ln) listDelNode(c->reply, ln);
    }
    c->reply_bytes = 0;
    c->sentlen = 0;
}

static int resp_process_input(client *c) {
    if (!c) return C_ERR;
    connection *saved = c->conn;
    c->conn = &g_resp_dummy_conn;
    int rc = processInputBuffer(c);
    c->conn = saved;
    return rc;
}

static int resp_send_close(int ring_idx, uint32_t cid) {
    unsigned char dummy = 0;
    uint16_t flags = RING_FLAG_RESP | (g_ctx.secure_enabled ? RING_FLAG_SECURE : 0);
    return queue_send(&g_ctx.resp[ring_idx], cid, MSG_CLOSE, flags, &dummy, 1);
}

static int resp_send_chunk(int ring_idx, uint32_t cid, const unsigned char *payload, uint32_t len) {
    if (len == 0) return 1;
    if (!payload) return C_ERR;
    if (!g_ctx.secure_enabled) {
        return queue_send(&g_ctx.resp[ring_idx], cid, MSG_DATA, RING_FLAG_RESP, payload, len);
    }
    unsigned char enc[RING_MAX_PAYLOAD];
    uint32_t enc_len = 0;
    const uint16_t flags = RING_FLAG_RESP | RING_FLAG_SECURE;
    const unsigned char *plain = payload;
    unsigned char staged[RING_MAX_PAYLOAD];
    uint32_t staged_len = 0;
    if (g_ctx.crypto_enabled) {
        if (crypto_priv_encrypt_then_decrypt((uint32_t)ring_idx,
                                             SEC_DIR_RESP,
                                             payload,
                                             len,
                                             staged,
                                             (uint32_t)sizeof(staged),
                                             &staged_len) != C_OK) {
            return C_ERR;
        }
        plain = staged;
        len = staged_len;
    }
    if (sec_encrypt((uint32_t)ring_idx, cid, MSG_DATA, flags, plain, len, SEC_DIR_RESP, enc, (uint32_t)sizeof(enc), &enc_len) != C_OK) {
        return C_ERR;
    }
    return queue_send(&g_ctx.resp[ring_idx], cid, MSG_DATA, flags, enc, enc_len);
}

static void resp_flush_one(RespConn *rc) {
    if (!rc) return;
    if (rc->ring_idx < 0 || rc->ring_idx >= g_ctx.ring_count) {
        rc->closing = 1;
        resp_pending_add(rc);
        return;
    }

    if (rc->out && rc->out_off < sdslen(rc->out)) {
        const uint32_t nonce_bytes = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
        const uint32_t tag_bytes = crypto_aead_chacha20poly1305_ietf_ABYTES;
        uint32_t chunk_max = RING_MAX_PAYLOAD;
        if (g_ctx.secure_enabled) chunk_max = RING_MAX_PAYLOAD - nonce_bytes - tag_bytes;

        while (rc->out && rc->out_off < sdslen(rc->out)) {
            size_t avail = sdslen(rc->out) - rc->out_off;
            uint32_t chunk = (uint32_t)((avail > chunk_max) ? chunk_max : avail);
            const unsigned char *p = (const unsigned char *)rc->out + rc->out_off;
            int sr = resp_send_chunk(rc->ring_idx, rc->cid, p, chunk);
            if (sr == 1) {
                rc->out_off += chunk;
                continue;
            }
            /* full or error -> retry next loop */
            resp_pending_add(rc);
            return;
        }
    }

    if (rc->out) {
        sdsfree(rc->out);
        rc->out = NULL;
        rc->out_off = 0;
    }

    if (rc->closing) {
        int sr = resp_send_close(rc->ring_idx, rc->cid);
        if (sr == 1) {
            resp_conn_free(rc);
            return;
        }
        resp_pending_add(rc);
        return;
    }

    resp_pending_remove(rc);
}

static void resp_flush_pending(int budget) {
    RespConn *rc = g_resp_pending_head;
    while (rc && budget-- > 0) {
        RespConn *next = rc->pending_next;
        resp_flush_one(rc);
        rc = next;
    }
}

static int tdx_ring_region_init(void *base, size_t size) {
    size_t header_size = align_up(sizeof(struct tdx_shm_header), 64U);
    size_t queue_bytes = (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE;
    size_t needed = header_size + (2U * queue_bytes);

    if (!base || size < needed) return C_ERR;

    memset(base, 0, needed);

    struct tdx_shm_header *hdr = (struct tdx_shm_header *)base;
    hdr->magic = TDX_SHM_MAGIC;
    hdr->version = TDX_SHM_VERSION;
    hdr->total_size = (uint64_t)size;
    hdr->flags = 0U;

    hdr->q12.capacity = TDX_SHM_QUEUE_CAPACITY;
    hdr->q12.slot_size = TDX_SHM_SLOT_SIZE;
    hdr->q12.data_offset = (uint32_t)header_size;

    hdr->q21.capacity = TDX_SHM_QUEUE_CAPACITY;
    hdr->q21.slot_size = TDX_SHM_SLOT_SIZE;
    hdr->q21.data_offset = (uint32_t)(header_size + queue_bytes);

    atomic_store_explicit(&hdr->q12.head, 0U, memory_order_relaxed);
    atomic_store_explicit(&hdr->q12.tail, 0U, memory_order_relaxed);
    atomic_store_explicit(&hdr->q21.head, 0U, memory_order_relaxed);
    atomic_store_explicit(&hdr->q21.tail, 0U, memory_order_relaxed);
    return C_OK;
}

static int tdx_ring_region_attach(void *base, size_t size, struct tdx_shm_region *out) {
    if (!base || !out) return C_ERR;

    struct tdx_shm_header *hdr = (struct tdx_shm_header *)base;
    if (hdr->magic != TDX_SHM_MAGIC || hdr->version != TDX_SHM_VERSION) return C_ERR;
    if (hdr->total_size == 0 || hdr->total_size > (uint64_t)size) return C_ERR;
    if (hdr->q12.slot_size != TDX_SHM_SLOT_SIZE || hdr->q21.slot_size != TDX_SHM_SLOT_SIZE) return C_ERR;
    if (hdr->q12.capacity != TDX_SHM_QUEUE_CAPACITY || hdr->q21.capacity != TDX_SHM_QUEUE_CAPACITY) return C_ERR;

    size_t queue_bytes = (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE;
    if ((size_t)hdr->q12.data_offset + queue_bytes > size) return C_ERR;
    if ((size_t)hdr->q21.data_offset + queue_bytes > size) return C_ERR;

    out->hdr = hdr;
    out->q12.q = &hdr->q12;
    out->q12.data = (uint8_t *)base + hdr->q12.data_offset;
    out->q21.q = &hdr->q21;
    out->q21.data = (uint8_t *)base + hdr->q21.data_offset;
    return C_OK;
}

static int queue_send(struct tdx_shm_queue_view *tx, uint32_t cid, uint16_t type, uint16_t flags, const unsigned char *payload, uint32_t len) {
    cxl_shm_delay();
    if (!tx || !tx->q || !tx->data || !payload) return C_ERR;
    if (len > RING_MAX_PAYLOAD) return C_ERR;

    struct tdx_shm_queue *q = tx->q;
    uint32_t cap = q->capacity;
    if (cap == 0U) return C_ERR;

    uint32_t head = atomic_load_explicit(&q->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint32_t next = ring_next(tail, cap);
    if (next == head) return 0; /* full */

    uint8_t *slot = tx->data + ((size_t)tail * q->slot_size);
    uint16_t msg_len = (uint16_t)(RING_SLOT_HDR_SIZE + len);
    memcpy(slot, &msg_len, sizeof(msg_len));

    struct ring_slot_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = len;
    hdr.reserved = 0;
    memcpy(slot + sizeof(msg_len), &hdr, sizeof(hdr));
    if (len) memcpy(slot + sizeof(msg_len) + sizeof(hdr), payload, len);

    atomic_store_explicit(&q->tail, next, memory_order_release);
    return 1;
}

static int queue_recv(struct tdx_shm_queue_view *rx, uint32_t *cid, uint16_t *type, uint16_t *flags, unsigned char **payload, uint32_t *len) {
    cxl_shm_delay();
    if (!rx || !rx->q || !rx->data || !cid || !type || !flags || !payload || !len) return C_ERR;

    struct tdx_shm_queue *q = rx->q;
    uint32_t cap = q->capacity;
    if (cap == 0U) return C_ERR;

    uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    if (head == tail) return 0; /* empty */

    uint8_t *slot = rx->data + ((size_t)head * q->slot_size);
    uint16_t msg_len = 0;
    memcpy(&msg_len, slot, sizeof(msg_len));
    if (msg_len < sizeof(struct ring_slot_hdr) || msg_len > TDX_SHM_MSG_MAX) return C_ERR;

    struct ring_slot_hdr hdr;
    memcpy(&hdr, slot + sizeof(msg_len), sizeof(hdr));
    if (hdr.len > (uint32_t)(msg_len - sizeof(hdr))) return C_ERR;
    if (hdr.len > RING_MAX_PAYLOAD) return C_ERR;

    *cid = hdr.cid;
    *type = hdr.type;
    *flags = hdr.flags;
    *len = hdr.len;
    *payload = slot + sizeof(msg_len) + sizeof(hdr);

    atomic_store_explicit(&q->head, ring_next(head, cap), memory_order_release);
    return 1;
}

static int send_binary_resp(int ring_idx, uint32_t cid, uint8_t status, const unsigned char *val, uint16_t vlen) {
    unsigned char buf[TDX_SHM_SLOT_SIZE];
    if ((uint32_t)(4U + (uint32_t)vlen) > RING_MAX_PAYLOAD) return C_ERR;
    buf[0] = status;
    buf[1] = (uint8_t)(vlen & 0xff);
    buf[2] = (uint8_t)((vlen >> 8) & 0xff);
    buf[3] = 0;
    if (vlen) memcpy(buf + 4, val, vlen);
    uint32_t plain_len = (uint32_t)(4U + (uint32_t)vlen);
    if (!g_ctx.secure_enabled) {
        return queue_send(&g_ctx.resp[ring_idx], cid, MSG_DATA, 0, buf, plain_len);
    }
    unsigned char enc[RING_MAX_PAYLOAD];
    uint32_t enc_len = 0;
    const unsigned char *plain = buf;
    unsigned char staged[RING_MAX_PAYLOAD];
    uint32_t staged_len = 0;
    if (g_ctx.crypto_enabled) {
        if (crypto_priv_encrypt_then_decrypt((uint32_t)ring_idx,
                                             SEC_DIR_RESP,
                                             buf,
                                             plain_len,
                                             staged,
                                             (uint32_t)sizeof(staged),
                                             &staged_len) != C_OK) {
            return C_ERR;
        }
        plain = staged;
        plain_len = staged_len;
    }
    if (sec_encrypt((uint32_t)ring_idx, cid, MSG_DATA, RING_FLAG_SECURE, plain, plain_len, SEC_DIR_RESP, enc, (uint32_t)sizeof(enc), &enc_len) != C_OK) {
        return C_ERR;
    }
    return queue_send(&g_ctx.resp[ring_idx], cid, MSG_DATA, RING_FLAG_SECURE, enc, enc_len);
}

static void handle_request(int ring_idx, uint32_t cid, uint16_t msg_type, uint16_t flags, unsigned char *payload, uint32_t len) {
    if (msg_type == MSG_CLOSE) {
        if (flags & RING_FLAG_RESP) {
            if (cid < g_resp_cap) {
                RespConn *rc = g_resp_map[cid];
                if (rc) resp_conn_free(rc);
            }
        }
        return;
    }
    if (msg_type != MSG_DATA) return;

    unsigned char dec[RING_MAX_PAYLOAD];
    if (g_ctx.secure_enabled) {
        if ((flags & RING_FLAG_SECURE) == 0) return;
        uint32_t dec_len = 0;
        if (sec_decrypt((uint32_t)ring_idx, cid, msg_type, flags, payload, len, dec, sizeof(dec), &dec_len) != C_OK) {
            return;
        }
        payload = dec;
        len = dec_len;
        if (len < 4) return;
    } else {
        if ((flags & RING_FLAG_SECURE) != 0) return;
    }

    if (flags & RING_FLAG_RESP) {
        RespConn *rc = resp_get_or_create(cid, ring_idx);
        if (!rc) return;
        if (!rc->c->querybuf) rc->c->querybuf = sdsempty();
        rc->c->querybuf = sdscatlen(rc->c->querybuf, payload, len);
        if (resp_process_input(rc->c) != C_OK) {
            rc->closing = 1;
        }
        resp_drain_client_output(rc);
        if (rc->out || rc->closing) resp_pending_add(rc);
        resp_flush_one(rc);
        return;
    }

    if (len < 4) return;
    uint8_t op = payload[0];
    uint8_t key_len = payload[1];
    uint16_t val_len = payload[2] | ((uint16_t)payload[3] << 8);
    size_t need = (size_t)4 + key_len + val_len;
    if (need > len || need > (size_t)RING_MAX_PAYLOAD) {
        serverLog(LL_WARNING, "tdx shm ring: drop cid=%u invalid lens key=%u val=%u len=%u", cid, key_len, val_len, len);
        return;
    }
    const unsigned char *key = payload + 4;
    const unsigned char *val = key + key_len;

    redisDb *db = &server.db[0];
    if (op == CXL_OP_GET) {
        robj *keyobj = createRawStringObject((const char *)key, key_len);
        robj *o = lookupKeyRead(db, keyobj);
        if (!o) {
            (void)send_binary_resp(ring_idx, cid, CXL_STATUS_MISS, NULL, 0);
            decrRefCount(keyobj);
            return;
        }
        if (o->type != OBJ_STRING) {
            (void)send_binary_resp(ring_idx, cid, CXL_STATUS_ERR, NULL, 0);
            decrRefCount(keyobj);
            return;
        }
        robj *dec = getDecodedObject(o);
        size_t blen = sdslen(dec->ptr);
        if (blen > 0xffff || (size_t)(4 + blen) > (size_t)RING_MAX_PAYLOAD) {
            (void)send_binary_resp(ring_idx, cid, CXL_STATUS_ERR, NULL, 0);
        } else {
            (void)send_binary_resp(ring_idx, cid, CXL_STATUS_OK, (unsigned char *)dec->ptr, (uint16_t)blen);
        }
        decrRefCount(dec);
        decrRefCount(keyobj);
    } else if (op == CXL_OP_SET) {
        robj *keyobj = createRawStringObject((const char *)key, key_len);
        robj *valobj = createStringObject((const char *)val, val_len);
        setKey(NULL, db, keyobj, &valobj, 0);
        signalModifiedKey(NULL, db, keyobj);
        notifyKeyspaceEvent(NOTIFY_STRING, "set", keyobj, db->id);
        server.dirty++;
        (void)send_binary_resp(ring_idx, cid, CXL_STATUS_OK, NULL, 0);
        decrRefCount(keyobj);
    } else {
        (void)send_binary_resp(ring_idx, cid, CXL_STATUS_ERR, NULL, 0);
    }
}

static int init_regions(void) {
    if (g_ctx.ring_count < 1 || g_ctx.ring_count > MAX_RINGS) return C_ERR;

    size_t header_size = align_up(sizeof(struct tdx_shm_header), 64U);
    size_t queue_bytes = (size_t)TDX_SHM_QUEUE_CAPACITY * (size_t)TDX_SHM_SLOT_SIZE;
    size_t min_region = header_size + (2U * queue_bytes);
    if (g_ctx.region_size < min_region) {
        serverLog(LL_WARNING, "tdx shm ring: region_size=%zu too small (need >= %zu)", g_ctx.region_size, min_region);
        return C_ERR;
    }
    if ((g_ctx.region_base % 4096) != 0 || (g_ctx.region_size % 4096) != 0) {
        serverLog(LL_WARNING, "tdx shm ring: region_base/size must be 4K-aligned (base=%zu size=%zu)",
                  g_ctx.region_base, g_ctx.region_size);
        return C_ERR;
    }
    if (g_ctx.region_base > g_ctx.map_size) return C_ERR;
    if ((size_t)g_ctx.ring_count > (g_ctx.map_size - g_ctx.region_base) / g_ctx.region_size) {
        serverLog(LL_WARNING,
                  "tdx shm ring: map too small for rings (map_size=%zu base=%zu ring_count=%d region_size=%zu)",
                  g_ctx.map_size, g_ctx.region_base, g_ctx.ring_count, g_ctx.region_size);
        return C_ERR;
    }

    for (int i = 0; i < g_ctx.ring_count; i++) {
        size_t off = g_ctx.region_base + (size_t)i * g_ctx.region_size;
        struct tdx_shm_region region;
        if (tdx_ring_region_attach(g_ctx.mm + off, g_ctx.region_size, &region) != C_OK) {
            if (tdx_ring_region_init(g_ctx.mm + off, g_ctx.region_size) != C_OK) {
                serverLog(LL_WARNING, "tdx shm ring: init failed (ring=%d off=%zu)", i, off);
                return C_ERR;
            }
            if (tdx_ring_region_attach(g_ctx.mm + off, g_ctx.region_size, &region) != C_OK) {
                serverLog(LL_WARNING, "tdx shm ring: attach failed after init (ring=%d off=%zu)", i, off);
                return C_ERR;
            }
        }

        /* Clean ring on each (re)attach. */
        atomic_store_explicit(&region.hdr->q12.head, 0U, memory_order_relaxed);
        atomic_store_explicit(&region.hdr->q12.tail, 0U, memory_order_relaxed);
        atomic_store_explicit(&region.hdr->q21.head, 0U, memory_order_relaxed);
        atomic_store_explicit(&region.hdr->q21.tail, 0U, memory_order_relaxed);

        g_ctx.req[i] = region.q21;
        g_ctx.resp[i] = region.q12;
        g_ctx.req_seen[i] = 0;
    }
    return C_OK;
}

int cxlRingInitFromEnv(void) {
    const char *path = getenv("CXL_RING_PATH");
    if (!path) return C_ERR;

    size_t map_size = DEFAULT_MAP_SIZE;
    size_t map_offset = 0;
    int ring_count = DEFAULT_RING_COUNT;

    const char *rc = getenv("CXL_RING_COUNT");
    if (rc) {
        int v = atoi(rc);
        if (v >= 1 && v <= MAX_RINGS) ring_count = v;
    }
    g_ctx.ring_count = ring_count;

    const char *ms = getenv("CXL_RING_MAP_SIZE");
    if (ms) {
        size_t v = 0;
        if (parse_size(ms, &v) == C_OK && v > 0) map_size = v;
    }
    const char *mo = getenv("CXL_RING_OFFSET");
    if (!mo || !mo[0]) mo = getenv("CXL_SHM_OFFSET");
    if (mo && mo[0]) {
        size_t v = 0;
        if (parse_size(mo, &v) == C_OK && v > 0) map_offset = v;
    }

    g_ctx.region_size = env_size("CXL_RING_REGION_SIZE", (size_t)TDX_SHM_DEFAULT_TOTAL_SIZE);
    g_ctx.region_base = env_size("CXL_RING_REGION_BASE", 0);

    g_ctx.shm_delay_ns = 0;
    const char *delay_ns = getenv("CXL_SHM_DELAY_NS");
    if (delay_ns && delay_ns[0]) {
        errno = 0;
        unsigned long long v = strtoull(delay_ns, NULL, 0);
        if (errno == 0) g_ctx.shm_delay_ns = (uint64_t)v;
    }

    g_ctx.fd = open(path, O_RDWR);
    if (g_ctx.fd < 0) {
        serverLog(LL_WARNING, "tdx shm ring: open(%s) failed: %s", path, strerror(errno));
        return C_ERR;
    }

    struct stat st;
    if (fstat(g_ctx.fd, &st) != 0) {
        serverLog(LL_WARNING, "tdx shm ring: fstat failed: %s", strerror(errno));
        close(g_ctx.fd);
        return C_ERR;
    }
    g_ctx.file_size = st.st_size;
    g_ctx.map_size = map_size ? map_size : st.st_size;
    g_ctx.map_offset = map_offset;

    long page = sysconf(_SC_PAGESIZE);
    if (page > 0 && (g_ctx.map_offset % (size_t)page) != 0) {
        serverLog(LL_WARNING, "tdx shm ring: CXL_RING_OFFSET=%zu is not page-aligned", g_ctx.map_offset);
        close(g_ctx.fd);
        return C_ERR;
    }
    if (S_ISREG(st.st_mode)) {
        if ((size_t)st.st_size <= g_ctx.map_offset) {
            serverLog(LL_WARNING, "tdx shm ring: map offset (%zu) exceeds file size (%zu)",
                      g_ctx.map_offset, (size_t)st.st_size);
            close(g_ctx.fd);
            return C_ERR;
        }
        if (g_ctx.map_size > (size_t)st.st_size - g_ctx.map_offset) {
            g_ctx.map_size = (size_t)st.st_size - g_ctx.map_offset;
        }
    }

    g_ctx.mm = mmap(NULL, g_ctx.map_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_ctx.fd, (off_t)g_ctx.map_offset);
    if (g_ctx.mm == MAP_FAILED) {
        serverLog(LL_WARNING, "tdx shm ring: mmap failed: %s", strerror(errno));
        close(g_ctx.fd);
        return C_ERR;
    }

    if (init_regions() != C_OK) {
        munmap(g_ctx.mm, g_ctx.map_size);
        close(g_ctx.fd);
        return C_ERR;
    }

    if (cxl_sec_init() != C_OK) {
        munmap(g_ctx.mm, g_ctx.map_size);
        close(g_ctx.fd);
        return C_ERR;
    }

    g_ctx.enabled = 1;
    if (!g_ctx.timer_id) {
        g_ctx.timer_id = aeCreateTimeEvent(server.el, 1, cxlRingCron, NULL, NULL);
        if (g_ctx.timer_id == AE_ERR) {
            serverLog(LL_WARNING, "tdx shm ring: failed to create timer event");
            g_ctx.timer_id = 0;
        }
    }

    serverLog(LL_NOTICE,
              "tdx shm ring: enabled path=%s map_size=%zu map_offset=%zu rings=%d region_base=%zu region_size=%zu cap=%u slot=%u",
              path, g_ctx.map_size, g_ctx.map_offset, g_ctx.ring_count, g_ctx.region_base, g_ctx.region_size,
              (unsigned)TDX_SHM_QUEUE_CAPACITY, (unsigned)TDX_SHM_SLOT_SIZE);
    if (g_ctx.shm_delay_ns) {
        serverLog(LL_NOTICE, "tdx shm ring: simulated shm delay enabled (CXL_SHM_DELAY_NS=%llu)",
                  (unsigned long long)g_ctx.shm_delay_ns);
    }
    return C_OK;
}

int cxlRingEnabled(void) {
    return g_ctx.enabled;
}

void cxlRingBeforeSleep(void) {
    if (!g_ctx.enabled) return;

    for (int r = 0; r < g_ctx.ring_count; r++) {
        uint32_t cid = 0, len = 0;
        uint16_t type = 0;
        uint16_t flags = 0;
        unsigned char *payload = NULL;
        int iter = 0;
        while (iter < 32768 && queue_recv(&g_ctx.req[r], &cid, &type, &flags, &payload, &len) > 0) {
            handle_request(r, cid, type, flags, payload, len);
            g_ctx.req_seen[r]++;
            if ((g_ctx.req_seen[r] % 20000ull) == 0) {
                unsigned head = atomic_load_explicit(&g_ctx.req[r].q->head, memory_order_relaxed);
                unsigned tail = atomic_load_explicit(&g_ctx.req[r].q->tail, memory_order_relaxed);
                serverLog(LL_NOTICE, "tdx shm ring[%d]: processed %llu req (head=%u tail=%u)",
                          r, g_ctx.req_seen[r], head, tail);
            }
            iter++;
        }
    }

    /* Best-effort flush of pending RESP replies / closes. */
    resp_flush_pending(1024);
}

static int cxlRingCron(aeEventLoop *eventLoop, long long id, void *clientData) {
    UNUSED(eventLoop);
    UNUSED(id);
    UNUSED(clientData);
    if (!g_ctx.enabled) return AE_NOMORE;
    cxlRingBeforeSleep();
    return 1;
}

void cxlRingShutdown(void) {
    if (!g_ctx.enabled) return;
    if (g_ctx.timer_id > 0 && server.el) {
        aeDeleteTimeEvent(server.el, g_ctx.timer_id);
    }
    if (g_resp_map) {
        for (size_t i = 0; i < g_resp_cap; i++) {
            RespConn *rc = g_resp_map[i];
            if (rc) resp_conn_free(rc);
        }
        zfree(g_resp_map);
        g_resp_map = NULL;
        g_resp_cap = 0;
        g_resp_pending_head = NULL;
    }
    if (g_ctx.mm && g_ctx.mm != MAP_FAILED) munmap(g_ctx.mm, g_ctx.map_size);
    if (g_ctx.fd >= 0) close(g_ctx.fd);
    memset(&g_ctx, 0, sizeof(g_ctx));
}
