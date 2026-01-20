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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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

static uint32_t ring_next(uint32_t v, uint32_t cap) {
    return (v + 1U) % cap;
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

static int queue_send(struct tdx_shm_queue_view *tx, uint32_t cid, uint16_t type, const unsigned char *payload, uint32_t len) {
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
    hdr.flags = 0;
    hdr.len = len;
    hdr.reserved = 0;
    memcpy(slot + sizeof(msg_len), &hdr, sizeof(hdr));
    if (len) memcpy(slot + sizeof(msg_len) + sizeof(hdr), payload, len);

    atomic_store_explicit(&q->tail, next, memory_order_release);
    return 1;
}

static int queue_recv(struct tdx_shm_queue_view *rx, uint32_t *cid, uint16_t *type, unsigned char **payload, uint32_t *len) {
    cxl_shm_delay();
    if (!rx || !rx->q || !rx->data || !cid || !type || !payload || !len) return C_ERR;

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
    return queue_send(&g_ctx.resp[ring_idx], cid, MSG_DATA, buf, (uint32_t)(4U + (uint32_t)vlen));
}

static void handle_request(int ring_idx, uint32_t cid, uint16_t msg_type, unsigned char *payload, uint32_t len) {
    if (msg_type == MSG_CLOSE) return;
    if (msg_type != MSG_DATA) return;
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
        unsigned long long v = strtoull(ms, NULL, 0);
        if (v > 0) map_size = (size_t)v;
    }
    const char *mo = getenv("CXL_RING_OFFSET");
    if (!mo || !mo[0]) mo = getenv("CXL_SHM_OFFSET");
    if (mo && mo[0]) {
        unsigned long long v = strtoull(mo, NULL, 0);
        if (v > 0) map_offset = (size_t)v;
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
        unsigned char *payload = NULL;
        int iter = 0;
        while (iter < 32768 && queue_recv(&g_ctx.req[r], &cid, &type, &payload, &len) > 0) {
            handle_request(r, cid, type, payload, len);
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
    if (g_ctx.mm && g_ctx.mm != MAP_FAILED) munmap(g_ctx.mm, g_ctx.map_size);
    if (g_ctx.fd >= 0) close(g_ctx.fd);
    memset(&g_ctx, 0, sizeof(g_ctx));
}

