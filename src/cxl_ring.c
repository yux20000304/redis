/* Shared-memory ring I/O for Redis, to bypass Python shim.
 * Protocol matches shim/cxl_shm.py (MSG_DATA=1, MSG_CLOSE=2).
 */

#include "server.h"
#include "sds.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#define CXL_MAGIC "CXLSHM1\0"
#define CXL_VERSION 2
#define MSG_DATA 1
#define MSG_CLOSE 2
#define DEFAULT_SLOT_SIZE 4096
#define DEFAULT_SLOTS (4096 * 104) /* 425,984 slots (104x baseline) */
#define DEFAULT_MAP_SIZE (1024 * 1024 * 1024ULL) /* 1GB */
#define DEFAULT_RING_COUNT 4
#define MAX_RINGS 8

#define CXL_SEC_TABLE_OFF 512
#define CXL_SEC_MAGIC "CXLSEC1\0"
#define CXL_SEC_VERSION 1
#define CXL_SEC_MAX_ENTRIES (MAX_RINGS * 2)
#define CXL_SEC_MAX_PRINCIPALS 16

#define SEC_PROTO_MAGIC 0x43534543u /* 'CSEC' */
#define SEC_PROTO_VERSION 1
#define SEC_REQ_ACCESS 1

#define SEC_STATUS_OK 0

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

/* Simple binary protocol (no RESP):
 * Request: u8 op (1=GET,2=SET), u8 key_len, u16 val_len (LE), key, val
 * Response: u8 status (0=OK,1=MISS,2=ERR), u16 val_len (LE), val (for GET hit)
 */
enum {
    CXL_OP_GET = 1,
    CXL_OP_SET = 2
};
enum {
    CXL_STATUS_OK = 0,
    CXL_STATUS_MISS = 1,
    CXL_STATUS_ERR = 2
};

typedef struct {
    uint32_t slot_size;
    uint32_t slots;
    size_t offset;
    size_t size;
} CxlRingConfig;

typedef struct {
    volatile uint64_t *head;
    volatile uint64_t *tail;
    unsigned char *slots_base;
    CxlRingConfig cfg;
} CxlRing;

typedef struct {
    int enabled;
    int fd;
    size_t map_size;
    size_t map_offset;
    size_t file_size;
    unsigned char *mm;
    uint64_t shm_delay_ns;
    uint64_t shm_pause_iters_per_ns_x1024;
    CxlRing req[MAX_RINGS];
    CxlRing resp[MAX_RINGS];
    int ring_count;
    long long timer_id;
    unsigned long long req_seen[MAX_RINGS];

    int sec_enabled;
    int sec_fd;
    uint32_t sec_node_id;
    uint64_t sec_principal;
} CxlRingCtx;

static CxlRingCtx g_ctx = {0};
static int cxlRingCron(aeEventLoop *eventLoop, long long id, void *clientData);

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

static int socket_connect(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        serverLog(LL_WARNING, "cxl sec: getaddrinfo(connect %s:%s): %s", host, port, gai_strerror(rc));
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

static CxlSecTable *sec_table(void) {
    if (!g_ctx.mm) return NULL;
    return (CxlSecTable *)(g_ctx.mm + CXL_SEC_TABLE_OFF);
}

static const CxlSecEntry *sec_find_entry(uint64_t off, uint64_t len) {
    if (!g_ctx.mm || len == 0) return NULL;
    uint64_t end = off + len;
    if (end < off) return NULL;
    CxlSecTable *t = sec_table();
    if (!t) return NULL;
    if (memcmp(t->magic, CXL_SEC_MAGIC, 8) != 0 || t->version != CXL_SEC_VERSION) return NULL;
    uint32_t n = t->entry_count;
    if (n > CXL_SEC_MAX_ENTRIES) n = CXL_SEC_MAX_ENTRIES;
    for (uint32_t i = 0; i < n; i++) {
        const CxlSecEntry *e = &t->entries[i];
        if (off >= e->start_off && end <= e->end_off) return e;
    }
    return NULL;
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

static int sec_connect_mgr(const char *addr) {
    char *host = NULL, *port = NULL;
    if (parse_hostport(addr, &host, &port) != 0) return -1;
    int fd = socket_connect(host, port);
    zfree(host);
    zfree(port);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

static int sec_wait_table_ready(unsigned timeout_ms) {
    unsigned waited = 0;
    while (waited < timeout_ms) {
        CxlSecTable *t = sec_table();
        if (t && memcmp(t->magic, CXL_SEC_MAGIC, 8) == 0 && t->version == CXL_SEC_VERSION) return 0;
        usleep(10 * 1000);
        waited += 10;
    }
    return -1;
}

static int sec_request_access(uint64_t off, uint32_t len) {
    if (g_ctx.sec_fd < 0) return -1;
    struct sec_req req;
    memset(&req, 0, sizeof(req));
    req.magic_be = htonl(SEC_PROTO_MAGIC);
    req.version_be = htons(SEC_PROTO_VERSION);
    req.type_be = htons(SEC_REQ_ACCESS);
    req.principal_be = htobe64(g_ctx.sec_principal);
    req.offset_be = htobe64(off);
    req.length_be = htonl(len);

    if (write_full(g_ctx.sec_fd, &req, sizeof(req)) != 0) {
        serverLog(LL_WARNING, "cxl sec: write access req failed: %s", strerror(errno));
        return -1;
    }
    struct sec_resp resp;
    ssize_t r = read_full(g_ctx.sec_fd, &resp, sizeof(resp));
    if (r != (ssize_t)sizeof(resp)) {
        serverLog(LL_WARNING, "cxl sec: read access resp failed (read=%zd): %s", r, (r < 0) ? strerror(errno) : "short read");
        return -1;
    }

    uint32_t magic = ntohl(resp.magic_be);
    uint16_t ver = ntohs(resp.version_be);
    uint16_t status = ntohs(resp.status_be);
    if (magic != SEC_PROTO_MAGIC || ver != SEC_PROTO_VERSION || status != SEC_STATUS_OK) {
        serverLog(LL_WARNING, "cxl sec: access denied/bad resp (magic=0x%x ver=%u status=%u)", magic, ver, status);
        return -1;
    }
    return 0;
}

static int sec_ensure_access(uint64_t off, uint64_t len) {
    if (!g_ctx.sec_enabled) return 0;
    for (int tries = 0; tries < 3; tries++) {
        const CxlSecEntry *e = sec_find_entry(off, len);
        if (!e) return -1;
        if (sec_entry_has_principal(e, g_ctx.sec_principal)) return 0;
        if (sec_request_access(off, (uint32_t)(len > 0xffffffffu ? 0xffffffffu : len)) != 0) return -1;
        usleep(1000);
    }
    return -1;
}

static void sec_crypt(unsigned char *buf, size_t len, uint8_t direction, uint8_t ring_idx, uint64_t seq,
                      const unsigned char key[crypto_stream_chacha20_ietf_KEYBYTES]) {
    unsigned char nonce[crypto_stream_chacha20_ietf_NONCEBYTES];
    memset(nonce, 0, sizeof(nonce));
    nonce[0] = direction;
    nonce[1] = ring_idx;
    memcpy(nonce + 4, &seq, sizeof(seq));
    crypto_stream_chacha20_ietf_xor(buf, buf, (unsigned long long)len, nonce, key);
}

static void ring_setup(CxlRing *r, unsigned char *base, const CxlRingConfig *cfg) {
    r->cfg = *cfg;
    r->head = (uint64_t *)(base + cfg->offset);
    r->tail = (uint64_t *)(base + cfg->offset + sizeof(uint64_t));
    size_t slots_base_off = cfg->offset + align_up(sizeof(uint64_t) * 2, 16);
    r->slots_base = base + slots_base_off;
}

static int ring_push(CxlRing *r, int ring_idx, uint8_t direction, uint32_t client_id, uint16_t msg_type,
                     const unsigned char *payload, uint32_t len) {
    cxl_shm_delay();
    uint64_t head = *r->head;
    uint64_t tail = *r->tail;
    if (head - tail >= r->cfg.slots) return 0; /* full */
    if (len > r->cfg.slot_size - 16) return -1;
    uint64_t idx = head % r->cfg.slots;
    unsigned char *ptr = r->slots_base + idx * r->cfg.slot_size;
    /* header: u32 client_id, u16 msg_type, u16 flags, u32 len, u32 reserved */
    uint32_t flags = 0, reserved = 0;
    memcpy(ptr, &client_id, sizeof(client_id));
    memcpy(ptr + 4, &msg_type, sizeof(msg_type));
    memcpy(ptr + 6, &flags, sizeof(flags));
    memcpy(ptr + 8, &len, sizeof(len));
    memcpy(ptr + 12, &reserved, sizeof(reserved));
    memcpy(ptr + 16, payload, len);
    if (r->cfg.slot_size > 16 + len) {
        memset(ptr + 16 + len, 0, r->cfg.slot_size - 16 - len);
    }
    if (g_ctx.sec_enabled) {
        size_t crypt_len = r->cfg.slot_size - 16;
        uint64_t payload_off = (uint64_t)(ptr + 16 - g_ctx.mm);
        if (sec_ensure_access(payload_off, crypt_len) != 0) return -1;
        const CxlSecEntry *e = sec_find_entry(payload_off, crypt_len);
        if (!e || !sec_entry_has_principal(e, g_ctx.sec_principal)) return -1;
        sec_crypt(g_ctx.mm + payload_off, crypt_len, direction, (uint8_t)ring_idx, head, e->key);
    }
    *r->head = head + 1;
    return 1;
}

static int ring_pop(CxlRing *r, int ring_idx, uint8_t direction, uint32_t *client_id, uint16_t *msg_type,
                    unsigned char **payload, uint32_t *len) {
    cxl_shm_delay();
    uint64_t head = *r->head;
    uint64_t tail = *r->tail;
    if (tail == head) return 0; /* empty */
    uint64_t idx = tail % r->cfg.slots;
    unsigned char *ptr = r->slots_base + idx * r->cfg.slot_size;
    memcpy(client_id, ptr, sizeof(uint32_t));
    memcpy(msg_type, ptr + 4, sizeof(uint16_t));
    memcpy(len, ptr + 8, sizeof(uint32_t));
    if (*len > r->cfg.slot_size - 16) {
        serverLog(LL_WARNING, "cxl ring payload too large (%u)", *len);
        *len = r->cfg.slot_size - 16;
    }
    if (g_ctx.sec_enabled) {
        size_t crypt_len = r->cfg.slot_size - 16;
        uint64_t payload_off = (uint64_t)(ptr + 16 - g_ctx.mm);
        if (sec_ensure_access(payload_off, crypt_len) != 0) return 0;
        const CxlSecEntry *e = sec_find_entry(payload_off, crypt_len);
        if (!e || !sec_entry_has_principal(e, g_ctx.sec_principal)) return 0;
        sec_crypt(g_ctx.mm + payload_off, crypt_len, direction, (uint8_t)ring_idx, tail, e->key);
    }
    *payload = ptr + 16;
    *r->tail = tail + 1;
    return 1;
}

static int send_binary_resp(int ring_idx, CxlRing *ring, uint32_t cid, uint8_t status, const unsigned char *val,
                            uint16_t vlen) {
    unsigned char buf[DEFAULT_SLOT_SIZE];
    if ((size_t)(4 + vlen) > ring->cfg.slot_size) return -1;
    buf[0] = status;
    buf[1] = (uint8_t)(vlen & 0xff);
    buf[2] = (uint8_t)((vlen >> 8) & 0xff);
    buf[3] = 0; /* reserved/padding */
    if (vlen) memcpy(buf + 4, val, vlen);
    return ring_push(ring, ring_idx, 2 /* RESP */, cid, MSG_DATA, buf, 4 + vlen);
}

static void handle_request(int ring_idx, uint32_t cid, uint16_t msg_type, unsigned char *payload, uint32_t len) {
    if (msg_type == MSG_CLOSE) return;
    if (msg_type != MSG_DATA) return;
    if (len < 4) return;
    uint8_t op = payload[0];
    uint8_t key_len = payload[1];
    uint16_t val_len = payload[2] | ((uint16_t)payload[3] << 8);
    size_t need = (size_t)4 + key_len + val_len;
    if (need > len || need > g_ctx.req[ring_idx].cfg.slot_size - 16) {
        serverLog(LL_WARNING, "cxl ring: drop cid=%u invalid lens key=%u val=%u len=%u", cid, key_len, val_len, len);
        return;
    }
    const unsigned char *key = payload + 4;
    const unsigned char *val = key + key_len;

    redisDb *db = &server.db[0];
    if (op == CXL_OP_GET) {
        robj *keyobj = createRawStringObject((const char *)key, key_len);
        robj *o = lookupKeyRead(db, keyobj);
        if (!o) {
            send_binary_resp(ring_idx, &g_ctx.resp[ring_idx], cid, CXL_STATUS_MISS, NULL, 0);
            decrRefCount(keyobj);
            return;
        }
        if (o->type != OBJ_STRING) {
            send_binary_resp(ring_idx, &g_ctx.resp[ring_idx], cid, CXL_STATUS_ERR, NULL, 0);
            decrRefCount(keyobj);
            return;
        }
        robj *dec = getDecodedObject(o);
        size_t blen = sdslen(dec->ptr);
        if (blen > 0xffff || 4 + blen > g_ctx.resp[ring_idx].cfg.slot_size - 16) {
            send_binary_resp(ring_idx, &g_ctx.resp[ring_idx], cid, CXL_STATUS_ERR, NULL, 0);
        } else {
            send_binary_resp(ring_idx,
                             &g_ctx.resp[ring_idx],
                             cid,
                             CXL_STATUS_OK,
                             (unsigned char *)dec->ptr,
                             (uint16_t)blen);
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
        send_binary_resp(ring_idx, &g_ctx.resp[ring_idx], cid, CXL_STATUS_OK, NULL, 0);
        decrRefCount(keyobj);
    } else {
        send_binary_resp(ring_idx, &g_ctx.resp[ring_idx], cid, CXL_STATUS_ERR, NULL, 0);
    }
}

static int init_layout(size_t map_size) {
    unsigned char *p = g_ctx.mm;
    /* header: magic(8) ver(u32) ring_count(u32) file_size(u64) then per-ring [req_off, req_sz, resp_off, resp_sz] */
    uint32_t ver = 0, ring_count = 0;
    uint64_t file_size = g_ctx.file_size;
    memcpy(&ver, p + 8, sizeof(uint32_t));
    memcpy(&ring_count, p + 12, sizeof(uint32_t));
    memcpy(&file_size, p + 16, sizeof(uint64_t));

    int header_ok = (memcmp(p, CXL_MAGIC, 8) == 0) && (ver == CXL_VERSION) &&
                    (ring_count >= 1 && ring_count <= MAX_RINGS);

    /* Validate existing layout against current mapping size.
     *
     * The shared-memory header persists across runs. If Redis re-attaches with
     * a smaller mapping (e.g., CXL_RING_MAP_SIZE reduced), the stored offsets
     * may point beyond the current mapping and cause a crash. In this case,
     * treat the header as invalid and reinitialize it for the current map_size.
     */
    if (header_ok) {
        if (g_ctx.ring_count > 0 && ring_count != (uint32_t)g_ctx.ring_count) {
            header_ok = 0;
        } else {
            size_t header_size = 16 + (size_t)ring_count * sizeof(uint64_t) * 4;
            size_t header_aligned = align_up(header_size, 4096);
            if (header_aligned > map_size) header_ok = 0;
            for (uint32_t i = 0; header_ok && i < ring_count; i++) {
                uint64_t req_off = 0, req_sz = 0, resp_off = 0, resp_sz = 0;
                memcpy(&req_off, p + 24 + i * 32, sizeof(uint64_t));
                memcpy(&req_sz, p + 32 + i * 32, sizeof(uint64_t));
                memcpy(&resp_off, p + 40 + i * 32, sizeof(uint64_t));
                memcpy(&resp_sz, p + 48 + i * 32, sizeof(uint64_t));

                if (req_off < header_aligned || resp_off < header_aligned) header_ok = 0;
                if ((req_off % 4096) || (resp_off % 4096)) header_ok = 0;
                if ((req_sz % 4096) || (resp_sz % 4096)) header_ok = 0;
                if (req_sz < 16 + DEFAULT_SLOT_SIZE) header_ok = 0;
                if (resp_sz < 16 + DEFAULT_SLOT_SIZE) header_ok = 0;
                if (req_off + req_sz > map_size) header_ok = 0;
                if (resp_off + resp_sz > map_size) header_ok = 0;
                if (resp_off < req_off + req_sz) header_ok = 0;
            }
        }
    }
    if (!header_ok) {
        ring_count = g_ctx.ring_count > 0 ? g_ctx.ring_count : DEFAULT_RING_COUNT;
        if (ring_count > MAX_RINGS) ring_count = MAX_RINGS;
        size_t header_size = 16 + ring_count * sizeof(uint64_t) * 4;
        size_t header_aligned = align_up(header_size, 4096);
        size_t slots = DEFAULT_SLOTS;
        size_t slot_size = DEFAULT_SLOT_SIZE;
        size_t ring_sz = align_up(16 + slot_size * slots, 4096);
        /* shrink slots until it fits */
        while (slots > 1 && header_aligned + ring_count * 2 * ring_sz > map_size) {
            slots /= 2;
            ring_sz = align_up(16 + slot_size * slots, 4096);
        }
        size_t off = header_aligned;
        memcpy(p, CXL_MAGIC, 8);
        ver = CXL_VERSION;
        memcpy(p + 8, &ver, sizeof(uint32_t));
        memcpy(p + 12, &ring_count, sizeof(uint32_t));
        memcpy(p + 16, &g_ctx.file_size, sizeof(uint64_t));
        for (int i = 0; i < (int)ring_count; i++) {
            uint64_t req_off = off;
            uint64_t req_sz = ring_sz;
            uint64_t resp_off = align_up(req_off + req_sz, 4096);
            uint64_t resp_sz = ring_sz;
            memcpy(p + 24 + i * 32, &req_off, sizeof(uint64_t));
            memcpy(p + 32 + i * 32, &req_sz, sizeof(uint64_t));
            memcpy(p + 40 + i * 32, &resp_off, sizeof(uint64_t));
            memcpy(p + 48 + i * 32, &resp_sz, sizeof(uint64_t));
            memset(p + req_off, 0, 16);  /* req head/tail */
            memset(p + resp_off, 0, 16); /* resp head/tail */
            off = align_up(resp_off + resp_sz, 4096);
        }
    } else {
        if (ring_count > MAX_RINGS) ring_count = MAX_RINGS;
    }

    g_ctx.ring_count = ring_count;
    for (int i = 0; i < g_ctx.ring_count; i++) {
        uint64_t req_off = 0, req_sz = 0, resp_off = 0, resp_sz = 0;
        memcpy(&req_off, p + 24 + i * 32, sizeof(uint64_t));
        memcpy(&req_sz, p + 32 + i * 32, sizeof(uint64_t));
        memcpy(&resp_off, p + 40 + i * 32, sizeof(uint64_t));
        memcpy(&resp_sz, p + 48 + i * 32, sizeof(uint64_t));
        g_ctx.req[i].cfg.slot_size = DEFAULT_SLOT_SIZE;
        g_ctx.resp[i].cfg.slot_size = DEFAULT_SLOT_SIZE;
        g_ctx.req[i].cfg.slots = (req_sz > 16) ? (req_sz - 16) / DEFAULT_SLOT_SIZE : 1;
        g_ctx.resp[i].cfg.slots = (resp_sz > 16) ? (resp_sz - 16) / DEFAULT_SLOT_SIZE : 1;
        g_ctx.req[i].cfg.offset = req_off;
        g_ctx.req[i].cfg.size = req_sz;
        g_ctx.resp[i].cfg.offset = resp_off;
        g_ctx.resp[i].cfg.size = resp_sz;
        ring_setup(&g_ctx.req[i], g_ctx.mm, &g_ctx.req[i].cfg);
        ring_setup(&g_ctx.resp[i], g_ctx.mm, &g_ctx.resp[i].cfg);
        /* Start with a clean ring each time Redis (re)attaches. */
        *g_ctx.req[i].head = *g_ctx.req[i].tail = 0;
        *g_ctx.resp[i].head = *g_ctx.resp[i].tail = 0;
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
        unsigned long long v = strtoull(ms, NULL, 0);
        if (v > 0) map_size = (size_t)v;
    }
    const char *mo = getenv("CXL_RING_OFFSET");
    if (!mo || !mo[0]) mo = getenv("CXL_SHM_OFFSET");
    if (mo && mo[0]) {
        unsigned long long v = strtoull(mo, NULL, 0);
        if (v > 0) map_offset = (size_t)v;
    }

    g_ctx.shm_delay_ns = 0;
    const char *delay_ns = getenv("CXL_SHM_DELAY_NS");
    if (delay_ns && delay_ns[0]) {
        errno = 0;
        unsigned long long v = strtoull(delay_ns, NULL, 0);
        if (errno == 0) g_ctx.shm_delay_ns = (uint64_t)v;
    }

    g_ctx.sec_enabled = 0;
    g_ctx.sec_fd = -1;

    g_ctx.fd = open(path, O_RDWR);
    if (g_ctx.fd < 0) {
        serverLog(LL_WARNING, "cxl ring: open(%s) failed: %s", path, strerror(errno));
        return C_ERR;
    }
    struct stat st;
    if (fstat(g_ctx.fd, &st) != 0) {
        serverLog(LL_WARNING, "cxl ring: fstat failed: %s", strerror(errno));
        close(g_ctx.fd);
        return C_ERR;
    }
    g_ctx.file_size = st.st_size;
    g_ctx.map_size = map_size ? map_size : st.st_size;
    g_ctx.map_offset = map_offset;
    long page = sysconf(_SC_PAGESIZE);
    if (page > 0 && (g_ctx.map_offset % (size_t)page) != 0) {
        serverLog(LL_WARNING, "cxl ring: CXL_RING_OFFSET=%zu is not page-aligned", g_ctx.map_offset);
        close(g_ctx.fd);
        return C_ERR;
    }
    if (S_ISREG(st.st_mode)) {
        if ((size_t)st.st_size <= g_ctx.map_offset) {
            serverLog(LL_WARNING, "cxl ring: map offset (%zu) exceeds file size (%zu)",
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
        serverLog(LL_WARNING, "cxl ring: mmap failed: %s", strerror(errno));
        close(g_ctx.fd);
        return C_ERR;
    }
    if (init_layout(g_ctx.map_size) != C_OK) {
        munmap(g_ctx.mm, g_ctx.map_size);
        close(g_ctx.fd);
        return C_ERR;
    }

    const char *sec_en = getenv("CXL_SEC_ENABLE");
    if (sec_en && sec_en[0] != '0') {
        const char *mgr = getenv("CXL_SEC_MGR");
        if (!mgr || !mgr[0]) {
            serverLog(LL_WARNING, "cxl sec: CXL_SEC_ENABLE=1 requires CXL_SEC_MGR=<ip:port>");
            munmap(g_ctx.mm, g_ctx.map_size);
            close(g_ctx.fd);
            return C_ERR;
        }
        unsigned timeout_ms = 10000;
        const char *tm = getenv("CXL_SEC_TIMEOUT_MS");
        if (tm) timeout_ms = (unsigned)strtoul(tm, NULL, 0);

        uint32_t node_id = 1;
        const char *nid = getenv("CXL_SEC_NODE_ID");
        if (nid) node_id = (uint32_t)strtoul(nid, NULL, 0);

        serverLog(LL_NOTICE, "cxl sec: enabling (mgr=%s node_id=%u timeout_ms=%u)", mgr, node_id, timeout_ms);

        if (sodium_init() < 0) {
            serverLog(LL_WARNING, "cxl sec: sodium_init failed");
            munmap(g_ctx.mm, g_ctx.map_size);
            close(g_ctx.fd);
            return C_ERR;
        }
        g_ctx.sec_enabled = 1;
        g_ctx.sec_node_id = node_id;
        g_ctx.sec_principal = ((uint64_t)node_id << 32) | (uint32_t)getpid();
        int fd = sec_connect_mgr(mgr);
        if (fd < 0) {
            int err = errno;
            serverLog(LL_WARNING, "cxl sec: connect failed (mgr=%s): %s", mgr, strerror(err));
            munmap(g_ctx.mm, g_ctx.map_size);
            close(g_ctx.fd);
            return C_ERR;
        }
        g_ctx.sec_fd = fd;
        if (sec_wait_table_ready(timeout_ms) != 0) {
            serverLog(LL_WARNING, "cxl sec: timeout waiting for table (offset=%u)", (unsigned)CXL_SEC_TABLE_OFF);
            close(g_ctx.sec_fd);
            g_ctx.sec_fd = -1;
            munmap(g_ctx.mm, g_ctx.map_size);
            close(g_ctx.fd);
            return C_ERR;
        }
        for (int i = 0; i < g_ctx.ring_count; i++) {
            (void)sec_request_access((uint64_t)g_ctx.req[i].cfg.offset, 1);
            (void)sec_request_access((uint64_t)g_ctx.resp[i].cfg.offset, 1);
        }
        serverLog(LL_NOTICE, "cxl sec: enabled (mgr=%s node_id=%u principal=%llu)", mgr, node_id,
                  (unsigned long long)g_ctx.sec_principal);
    }

    g_ctx.enabled = 1;
    if (!g_ctx.timer_id) {
        g_ctx.timer_id = aeCreateTimeEvent(server.el, 1, cxlRingCron, NULL, NULL);
        if (g_ctx.timer_id == AE_ERR) {
            serverLog(LL_WARNING, "cxl ring: failed to create timer event");
            g_ctx.timer_id = 0;
        }
    }
    serverLog(LL_NOTICE, "cxl ring: enabled path=%s map_size=%zu map_offset=%zu rings=%d slots_per_ring=%u",
              path, g_ctx.map_size, g_ctx.map_offset, g_ctx.ring_count, g_ctx.req[0].cfg.slots);
    if (g_ctx.shm_delay_ns) {
        serverLog(LL_NOTICE, "cxl ring: simulated shm delay enabled (CXL_SHM_DELAY_NS=%llu)",
                  (unsigned long long)g_ctx.shm_delay_ns);
    }
    return C_OK;
}

int cxlRingEnabled(void) {
    return g_ctx.enabled;
}

void cxlRingBeforeSleep(void) {
    if (!g_ctx.enabled) return;

    /* Drain requests from each ring; allow larger batch to reduce per-iteration overhead. */
    for (int r = 0; r < g_ctx.ring_count; r++) {
        uint32_t cid, len;
        uint16_t type;
        unsigned char *payload;
        int iter = 0;
        while (iter < 32768 && ring_pop(&g_ctx.req[r], r, 1 /* REQ */, &cid, &type, &payload, &len)) {
            handle_request(r, cid, type, payload, len);
            g_ctx.req_seen[r]++;
            if ((g_ctx.req_seen[r] % 20000ull) == 0) {
                serverLog(LL_NOTICE, "cxl ring[%d]: processed %llu req (head=%llu tail=%llu)",
                          r,
                          g_ctx.req_seen[r],
                          (unsigned long long)(*g_ctx.req[r].head),
                          (unsigned long long)(*g_ctx.req[r].tail));
            }
            iter++;
        }
    }
}

static int cxlRingCron(aeEventLoop *eventLoop, long long id, void *clientData) {
    UNUSED(eventLoop);
    UNUSED(id);
    UNUSED(clientData);
    if (!g_ctx.enabled) return AE_NOMORE;
    cxlRingBeforeSleep();
    return 1; /* run again in 1ms */
}

void cxlRingShutdown(void) {
    if (!g_ctx.enabled) return;
    if (g_ctx.timer_id > 0 && server.el) {
        aeDeleteTimeEvent(server.el, g_ctx.timer_id);
    }
    if (g_ctx.sec_enabled && g_ctx.sec_fd >= 0) close(g_ctx.sec_fd);
    if (g_ctx.mm && g_ctx.mm != MAP_FAILED) munmap(g_ctx.mm, g_ctx.map_size);
    if (g_ctx.fd >= 0) close(g_ctx.fd);
    memset(&g_ctx, 0, sizeof(g_ctx));
}
