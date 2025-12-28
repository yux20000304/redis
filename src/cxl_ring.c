/* Shared-memory ring I/O for Redis, to bypass Python shim.
 * Protocol matches shim/cxl_shm.py (MSG_DATA=1, MSG_CLOSE=2).
 */

#include "server.h"
#include "sds.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define CXL_MAGIC "CXLSHM1\0"
#define CXL_VERSION 2
#define MSG_DATA 1
#define MSG_CLOSE 2
#define DEFAULT_SLOT_SIZE 4096
#define DEFAULT_SLOTS (4096 * 104) /* 425,984 slots (104x baseline) */
#define DEFAULT_MAP_SIZE (1024 * 1024 * 1024ULL) /* 1GB */
#define DEFAULT_RING_COUNT 4
#define MAX_RINGS 8

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
    size_t file_size;
    unsigned char *mm;
    CxlRing req[MAX_RINGS];
    CxlRing resp[MAX_RINGS];
    int ring_count;
    long long timer_id;
    unsigned long long req_seen[MAX_RINGS];
} CxlRingCtx;

static CxlRingCtx g_ctx = {0};
static int cxlRingCron(aeEventLoop *eventLoop, long long id, void *clientData);

static inline size_t align_up(size_t x, size_t a) {
    return (x + a - 1) / a * a;
}

static void ring_setup(CxlRing *r, unsigned char *base, const CxlRingConfig *cfg) {
    r->cfg = *cfg;
    r->head = (uint64_t *)(base + cfg->offset);
    r->tail = (uint64_t *)(base + cfg->offset + sizeof(uint64_t));
    size_t slots_base_off = cfg->offset + align_up(sizeof(uint64_t) * 2, 16);
    r->slots_base = base + slots_base_off;
}

static int ring_push(CxlRing *r, uint32_t client_id, uint16_t msg_type, const unsigned char *payload, uint32_t len) {
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
    *r->head = head + 1;
    return 1;
}

static int ring_pop(CxlRing *r, uint32_t *client_id, uint16_t *msg_type, unsigned char **payload, uint32_t *len) {
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
    *payload = ptr + 16;
    *r->tail = tail + 1;
    return 1;
}

static int send_binary_resp(CxlRing *ring, uint32_t cid, uint8_t status, const unsigned char *val, uint16_t vlen) {
    unsigned char buf[DEFAULT_SLOT_SIZE];
    if ((size_t)(4 + vlen) > ring->cfg.slot_size) return -1;
    buf[0] = status;
    buf[1] = (uint8_t)(vlen & 0xff);
    buf[2] = (uint8_t)((vlen >> 8) & 0xff);
    buf[3] = 0; /* reserved/padding */
    if (vlen) memcpy(buf + 4, val, vlen);
    return ring_push(ring, cid, MSG_DATA, buf, 4 + vlen);
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
            send_binary_resp(&g_ctx.resp[ring_idx], cid, CXL_STATUS_MISS, NULL, 0);
            decrRefCount(keyobj);
            return;
        }
        if (o->type != OBJ_STRING) {
            send_binary_resp(&g_ctx.resp[ring_idx], cid, CXL_STATUS_ERR, NULL, 0);
            decrRefCount(keyobj);
            return;
        }
        robj *dec = getDecodedObject(o);
        size_t blen = sdslen(dec->ptr);
        if (blen > 0xffff || 4 + blen > g_ctx.resp[ring_idx].cfg.slot_size - 16) {
            send_binary_resp(&g_ctx.resp[ring_idx], cid, CXL_STATUS_ERR, NULL, 0);
        } else {
            send_binary_resp(&g_ctx.resp[ring_idx], cid, CXL_STATUS_OK, (unsigned char *)dec->ptr, (uint16_t)blen);
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
        send_binary_resp(&g_ctx.resp[ring_idx], cid, CXL_STATUS_OK, NULL, 0);
        decrRefCount(keyobj);
    } else {
        send_binary_resp(&g_ctx.resp[ring_idx], cid, CXL_STATUS_ERR, NULL, 0);
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
    if (g_ctx.map_size > (size_t)st.st_size) g_ctx.map_size = st.st_size;
    g_ctx.mm = mmap(NULL, g_ctx.map_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_ctx.fd, 0);
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
    g_ctx.enabled = 1;
    if (!g_ctx.timer_id) {
        g_ctx.timer_id = aeCreateTimeEvent(server.el, 1, cxlRingCron, NULL, NULL);
        if (g_ctx.timer_id == AE_ERR) {
            serverLog(LL_WARNING, "cxl ring: failed to create timer event");
            g_ctx.timer_id = 0;
        }
    }
    serverLog(LL_NOTICE, "cxl ring: enabled path=%s map_size=%zu rings=%d slots_per_ring=%u",
              path, g_ctx.map_size, g_ctx.ring_count, g_ctx.req[0].cfg.slots);
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
        while (iter < 32768 && ring_pop(&g_ctx.req[r], &cid, &type, &payload, &len)) {
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
    if (g_ctx.mm && g_ctx.mm != MAP_FAILED) munmap(g_ctx.mm, g_ctx.map_size);
    if (g_ctx.fd >= 0) close(g_ctx.fd);
    memset(&g_ctx, 0, sizeof(g_ctx));
}
