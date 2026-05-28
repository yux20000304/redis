#include "server.h"
#include "cxl_ring.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CXL_RING_DEFAULT_MAP_SIZE (1024ULL * 1024ULL * 1024ULL)
#define CXL_RING_DEFAULT_COUNT 4
typedef struct CxlRingCtx {
    int enabled;
    int fd;
    uint8_t *mm;
    size_t map_size;
    size_t map_offset;
    int ring_count;
    size_t region_base;
    size_t region_size;
    long long timer_id;
    struct cxl_ring_region *rings;
    unsigned long long *processed;

    int stats_enabled;
    char stats_path[PATH_MAX];
    atomic_uint_fast64_t stats_requests;
    atomic_uint_fast64_t stats_responses;
} CxlRingCtx;

static CxlRingCtx g_cxl_ring = {0};
static int cxlRingCron(aeEventLoop *eventLoop, long long id, void *clientData);

static int cxlRingDebugEnabled(void) {
    static int initialized = 0;
    static int enabled = 0;
    if (!initialized) {
        const char *value = getenv("CXL_RING_DEBUG");
        enabled = value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
        initialized = 1;
    }
    return enabled;
}

static int cxlRingParseSize(const char *arg, size_t *out) {
    if (arg == NULL || out == NULL || arg[0] == '\0') return C_ERR;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(arg, &end, 0);
    if (errno != 0 || end == arg) return C_ERR;

    unsigned long long multiplier = 1ULL;
    if (end != NULL && *end != '\0') {
        if (end[1] != '\0' &&
            !((end[1] == 'B' || end[1] == 'b') && end[2] == '\0') &&
            !((end[1] == 'I' || end[1] == 'i') &&
              (end[2] == 'B' || end[2] == 'b') && end[3] == '\0'))
            return C_ERR;
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

    if (value > ULLONG_MAX / multiplier) return C_ERR;
    unsigned long long bytes = value * multiplier;
    if (bytes > (unsigned long long)SIZE_MAX) return C_ERR;
    *out = (size_t)bytes;
    return C_OK;
}

static size_t cxlRingEnvSize(const char *name, size_t def) {
    const char *value = getenv(name);
    size_t parsed = 0;
    if (value == NULL || value[0] == '\0') return def;
    if (cxlRingParseSize(value, &parsed) != C_OK) return def;
    return parsed;
}

static int cxlRingSendPayload(int ring_idx, uint32_t cid,
                              const uint8_t *plain, uint32_t plain_len) {
    if (ring_idx < 0 || ring_idx >= g_cxl_ring.ring_count) return C_ERR;
    return cxlRingQueueSend(&g_cxl_ring.rings[ring_idx].q12, cid,
                            CXL_RING_MSG_DATA, 0U, plain, plain_len);
}

static int cxlRingSendResp(int ring_idx, uint32_t cid, uint8_t status,
                           const uint8_t *value, uint16_t value_len) {
    uint8_t buf[CXL_RING_MAX_PAYLOAD];
    if ((uint32_t)value_len + 4U > CXL_RING_MAX_PAYLOAD) return C_ERR;
    buf[0] = status;
    buf[1] = (uint8_t)(value_len & 0xffU);
    buf[2] = (uint8_t)((value_len >> 8) & 0xffU);
    buf[3] = 0U;
    if (value_len != 0U && value != NULL)
        memcpy(buf + 4U, value, value_len);
    return cxlRingSendPayload(ring_idx, cid, buf, (uint32_t)value_len + 4U);
}

static int cxlRingParseSequentialKey(const uint8_t *key, uint8_t key_len,
                                     size_t *prefix_len, int *digit_width,
                                     unsigned long long *start_id) {
    if (key == NULL || key_len == 0U || prefix_len == NULL ||
        digit_width == NULL || start_id == NULL)
        return C_ERR;

    int pos = key_len;
    while (pos > 0 && key[pos - 1] >= '0' && key[pos - 1] <= '9')
        pos--;
    if (pos == key_len) return C_ERR;

    unsigned long long id = 0;
    for (int i = pos; i < key_len; i++) {
        unsigned digit = (unsigned)(key[i] - '0');
        if (id > (ULLONG_MAX - digit) / 10ULL)
            return C_ERR;
        id = id * 10ULL + digit;
    }

    *prefix_len = (size_t)pos;
    *digit_width = key_len - pos;
    *start_id = id;
    return C_OK;
}

static void cxlRingWriteU32(uint8_t *buf, uint32_t value) {
    buf[0] = (uint8_t)(value & 0xffU);
    buf[1] = (uint8_t)((value >> 8) & 0xffU);
    buf[2] = (uint8_t)((value >> 16) & 0xffU);
    buf[3] = (uint8_t)((value >> 24) & 0xffU);
}

static int cxlRingScanSequential(redisDb *db, const uint8_t *key,
                                 uint8_t key_len, uint16_t scan_len,
                                 uint32_t *items_out,
                                 uint32_t *bytes_out) {
    size_t prefix_len = 0;
    int digit_width = 0;
    unsigned long long start_id = 0;
    if (cxlRingParseSequentialKey(key, key_len, &prefix_len,
                                  &digit_width, &start_id) != C_OK)
        return C_ERR;

    uint32_t items = 0;
    uint32_t bytes = 0;
    char keybuf[256];

    for (uint16_t i = 0; i < scan_len; i++) {
        int len = snprintf(keybuf, sizeof(keybuf), "%.*s%0*llu",
                           (int)prefix_len, (const char *)key,
                           digit_width, start_id + i);
        if (len <= 0 || len >= (int)sizeof(keybuf))
            return C_ERR;

        robj *keyobj = createRawStringObject(keybuf, len);
        robj *obj = lookupKeyRead(db, keyobj);
        if (obj != NULL && obj->type == OBJ_STRING) {
            robj *decoded = getDecodedObject(obj);
            size_t value_len = sdslen(decoded->ptr);
            items++;
            if (value_len > UINT32_MAX - bytes)
                bytes = UINT32_MAX;
            else
                bytes += (uint32_t)value_len;
            decrRefCount(decoded);
        }
        decrRefCount(keyobj);
    }

    *items_out = items;
    *bytes_out = bytes;
    return C_OK;
}

static void cxlRingHandleRequest(int ring_idx, uint32_t cid, uint16_t msg_type,
                                 uint16_t flags, uint8_t *payload,
                                 uint32_t len) {
    if (cxlRingDebugEnabled()) {
        serverLog(LL_NOTICE,
                  "cxl ring: recv ring=%d cid=%u type=%u len=%u",
                  ring_idx, (unsigned)cid, (unsigned)msg_type, (unsigned)len);
    }
    if (msg_type == CXL_RING_MSG_CLOSE) {
        UNUSED(flags);
        UNUSED(payload);
        UNUSED(len);
        serverLog(LL_NOTICE, "cxl ring: shutdown requested by cid=%u ring=%d",
                  (unsigned)cid, ring_idx);
        if (prepareForShutdown(SHUTDOWN_NOSAVE | SHUTDOWN_NOW) == C_OK)
            exit(0);
        serverLog(LL_WARNING, "cxl ring: shutdown request failed");
        return;
    }
    if (msg_type != CXL_RING_MSG_DATA) return;
    UNUSED(flags);

    if (len < 4U) return;
    uint8_t op = payload[0];
    uint8_t key_len = payload[1];
    uint16_t value_len = (uint16_t)payload[2] | ((uint16_t)payload[3] << 8);
    size_t need = 4U + (size_t)key_len;
    if (op == CXL_OP_SET)
        need += (size_t)value_len;
    if (need > len || key_len == 0U) {
        (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_ERR, NULL, 0);
        return;
    }

    const uint8_t *key = payload + 4U;
    const uint8_t *value = key + key_len;
    redisDb *db = &server.db[0];

    if (op == CXL_OP_GET) {
        robj *keyobj = createRawStringObject((const char *)key, key_len);
        robj *obj = lookupKeyRead(db, keyobj);
        if (obj == NULL) {
            (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_MISS, NULL, 0);
            decrRefCount(keyobj);
            return;
        }
        if (obj->type != OBJ_STRING) {
            (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_ERR, NULL, 0);
            decrRefCount(keyobj);
            return;
        }

        robj *decoded = getDecodedObject(obj);
        size_t out_len = sdslen(decoded->ptr);
        if (out_len > UINT16_MAX ||
            out_len + 4U > (size_t)CXL_RING_MAX_PAYLOAD) {
            (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_ERR, NULL, 0);
        } else {
            (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_OK,
                                  (const uint8_t *)decoded->ptr,
                                  (uint16_t)out_len);
        }
        decrRefCount(decoded);
        decrRefCount(keyobj);
    } else if (op == CXL_OP_SET) {
        robj *keyobj = createRawStringObject((const char *)key, key_len);
        robj *valobj = createStringObject((const char *)value, value_len);
        setKey(NULL, db, keyobj, &valobj, 0);
        notifyKeyspaceEvent(NOTIFY_STRING, "set", keyobj, db->id);
        server.dirty++;
        (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_OK, NULL, 0);
        decrRefCount(keyobj);
    } else if (op == CXL_OP_DEL) {
        robj *keyobj = createRawStringObject((const char *)key, key_len);
        int removed = dbDelete(db, keyobj);
        if (removed) {
            signalModifiedKey(NULL, db, keyobj);
            notifyKeyspaceEvent(NOTIFY_GENERIC, "del", keyobj, db->id);
            server.dirty++;
            (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_OK, NULL, 0);
        } else {
            (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_MISS, NULL, 0);
        }
        decrRefCount(keyobj);
    } else if (op == CXL_OP_SCAN) {
        uint32_t items = 0, bytes = 0;
        uint8_t out[8];
        if (value_len == 0U ||
            cxlRingScanSequential(db, key, key_len, value_len,
                                  &items, &bytes) != C_OK) {
            (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_ERR, NULL, 0);
            return;
        }
        cxlRingWriteU32(out, items);
        cxlRingWriteU32(out + 4, bytes);
        (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_OK, out, sizeof(out));
    } else {
        (void)cxlRingSendResp(ring_idx, cid, CXL_STATUS_ERR, NULL, 0);
    }
}

static void cxlRingWriteStats(void) {
    if (!g_cxl_ring.stats_enabled || g_cxl_ring.stats_path[0] == '\0') return;
    FILE *f = fopen(g_cxl_ring.stats_path, "w");
    if (f == NULL) return;
    fprintf(f,
            "{\n"
            "  \"pid\": %d,\n"
            "  \"requests\": %llu,\n"
            "  \"responses\": %llu\n"
            "}\n",
            (int)getpid(),
            (unsigned long long)atomic_load_explicit(&g_cxl_ring.stats_requests, memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(&g_cxl_ring.stats_responses, memory_order_relaxed));
    fclose(f);
}

static int cxlRingOpenAndMap(const char *path) {
    g_cxl_ring.fd = open(path, O_RDWR);
    if (g_cxl_ring.fd < 0 && errno == ENOENT && path[0] != '/') {
        g_cxl_ring.fd = open(path, O_RDWR | O_CREAT, 0600);
    }
    if (g_cxl_ring.fd < 0 && errno == ENOENT && strncmp(path, "/dev/", 5) != 0) {
        g_cxl_ring.fd = open(path, O_RDWR | O_CREAT, 0600);
    }
    if (g_cxl_ring.fd < 0) {
        serverLog(LL_WARNING, "cxl ring: open(%s) failed: %s", path, strerror(errno));
        return C_ERR;
    }

    struct stat st;
    int have_stat = fstat(g_cxl_ring.fd, &st) == 0;
    if (!have_stat && strncmp(path, "/dev/", 5) != 0) {
        serverLog(LL_WARNING, "cxl ring: fstat failed: %s", strerror(errno));
        close(g_cxl_ring.fd);
        g_cxl_ring.fd = -1;
        return C_ERR;
    }

    if (have_stat && S_ISREG(st.st_mode)) {
        off_t needed = (off_t)(g_cxl_ring.map_offset + g_cxl_ring.map_size);
        if (st.st_size < needed && ftruncate(g_cxl_ring.fd, needed) != 0) {
            serverLog(LL_WARNING, "cxl ring: ftruncate failed: %s", strerror(errno));
            close(g_cxl_ring.fd);
            g_cxl_ring.fd = -1;
            return C_ERR;
        }
    }

    long page = sysconf(_SC_PAGESIZE);
    if (page > 0 && (g_cxl_ring.map_offset % (size_t)page) != 0) {
        serverLog(LL_WARNING, "cxl ring: CXL_RING_OFFSET=%zu is not page-aligned",
                  g_cxl_ring.map_offset);
        close(g_cxl_ring.fd);
        g_cxl_ring.fd = -1;
        return C_ERR;
    }

    g_cxl_ring.mm = mmap(NULL, g_cxl_ring.map_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, g_cxl_ring.fd, (off_t)g_cxl_ring.map_offset);
    if (g_cxl_ring.mm == MAP_FAILED) {
        serverLog(LL_WARNING, "cxl ring: mmap failed: %s", strerror(errno));
        close(g_cxl_ring.fd);
        g_cxl_ring.fd = -1;
        g_cxl_ring.mm = NULL;
        return C_ERR;
    }
    return C_OK;
}

static int cxlRingInitRegions(void) {
    if (g_cxl_ring.ring_count < 1 || g_cxl_ring.ring_count > CXL_RING_MAX_RINGS)
        return C_ERR;
    if ((g_cxl_ring.region_base % 4096U) != 0U ||
        (g_cxl_ring.region_size % 4096U) != 0U) {
        serverLog(LL_WARNING,
                  "cxl ring: CXL_RING_REGION_BASE/SIZE must be 4K-aligned");
        return C_ERR;
    }
    if (g_cxl_ring.region_size < cxlRingDefaultRegionSize()) {
        serverLog(LL_WARNING, "cxl ring: region_size=%zu too small, need >= %zu",
                  g_cxl_ring.region_size, cxlRingDefaultRegionSize());
        return C_ERR;
    }
    if ((size_t)g_cxl_ring.ring_count >
        (g_cxl_ring.map_size - g_cxl_ring.region_base) / g_cxl_ring.region_size) {
        serverLog(LL_WARNING,
                  "cxl ring: map too small for rings (map_size=%zu base=%zu count=%d region_size=%zu)",
                  g_cxl_ring.map_size, g_cxl_ring.region_base,
                  g_cxl_ring.ring_count, g_cxl_ring.region_size);
        return C_ERR;
    }

    g_cxl_ring.rings = zcalloc(sizeof(*g_cxl_ring.rings) * g_cxl_ring.ring_count);
    g_cxl_ring.processed = zcalloc(sizeof(*g_cxl_ring.processed) * g_cxl_ring.ring_count);
    if (g_cxl_ring.rings == NULL || g_cxl_ring.processed == NULL) return C_ERR;

    for (int i = 0; i < g_cxl_ring.ring_count; i++) {
        size_t off = g_cxl_ring.region_base + (size_t)i * g_cxl_ring.region_size;
        void *base = g_cxl_ring.mm + off;
        if (cxlRingRegionAttach(base, g_cxl_ring.region_size,
                                &g_cxl_ring.rings[i]) != 0) {
            if (cxlRingRegionInit(base, g_cxl_ring.region_size) != 0) {
                serverLog(LL_WARNING, "cxl ring: init failed for ring=%d off=%zu", i, off);
                return C_ERR;
            }
            if (cxlRingRegionAttach(base, g_cxl_ring.region_size,
                                    &g_cxl_ring.rings[i]) != 0) {
                serverLog(LL_WARNING, "cxl ring: attach failed for ring=%d off=%zu", i, off);
                return C_ERR;
            }
        }
        cxlRingRegionSetReady(&g_cxl_ring.rings[i], 0);
        cxlRingRegionReset(&g_cxl_ring.rings[i]);
        cxlRingRegionSetReady(&g_cxl_ring.rings[i], 1);
    }
    return C_OK;
}

int cxlRingInitFromEnv(void) {
    const char *path = getenv("CXL_RING_PATH");
    if (path == NULL || path[0] == '\0') return C_ERR;
    if (g_cxl_ring.enabled) return C_OK;

    g_cxl_ring.fd = -1;
    g_cxl_ring.map_size = cxlRingEnvSize("CXL_RING_MAP_SIZE",
                                         CXL_RING_DEFAULT_MAP_SIZE);
    g_cxl_ring.map_offset = cxlRingEnvSize("CXL_RING_OFFSET", 0U);
    if (g_cxl_ring.map_offset == 0U)
        g_cxl_ring.map_offset = cxlRingEnvSize("CXL_SHM_OFFSET", 0U);
    g_cxl_ring.region_base = cxlRingEnvSize("CXL_RING_REGION_BASE", 0U);
    g_cxl_ring.region_size = cxlRingEnvSize("CXL_RING_REGION_SIZE",
                                            cxlRingDefaultRegionSize());
    g_cxl_ring.ring_count = CXL_RING_DEFAULT_COUNT;

    const char *count = getenv("CXL_RING_COUNT");
    if (count != NULL && count[0] != '\0') {
        int parsed = atoi(count);
        if (parsed >= 1 && parsed <= CXL_RING_MAX_RINGS)
            g_cxl_ring.ring_count = parsed;
    }

    if (cxlRingOpenAndMap(path) != C_OK) goto fail;
    if (cxlRingInitRegions() != C_OK) goto fail;

    const char *stats_path = getenv("CXL_RING_STATS_OUT");
    if (stats_path != NULL && stats_path[0] != '\0') {
        snprintf(g_cxl_ring.stats_path, sizeof(g_cxl_ring.stats_path),
                 "%s", stats_path);
        g_cxl_ring.stats_enabled = 1;
    }

    g_cxl_ring.enabled = 1;
    g_cxl_ring.timer_id = aeCreateTimeEvent(server.el, 1, cxlRingCron, NULL, NULL);
    if (g_cxl_ring.timer_id == AE_ERR) {
        serverLog(LL_WARNING, "cxl ring: failed to create timer event");
        g_cxl_ring.timer_id = 0;
    }
    aeSetDontWait(server.el, 1);
    atexit(cxlRingShutdown);

    serverLog(LL_NOTICE,
              "cxl ring: enabled path=%s map_size=%zu offset=%zu rings=%d region_base=%zu region_size=%zu cap=%u slot=%u",
              path, g_cxl_ring.map_size, g_cxl_ring.map_offset,
              g_cxl_ring.ring_count, g_cxl_ring.region_base,
              g_cxl_ring.region_size, (unsigned)CXL_RING_QUEUE_CAPACITY,
              (unsigned)CXL_RING_SLOT_SIZE);
    return C_OK;

fail:
    if (g_cxl_ring.mm != NULL && g_cxl_ring.mm != MAP_FAILED) {
        munmap(g_cxl_ring.mm, g_cxl_ring.map_size);
        g_cxl_ring.mm = NULL;
    }
    if (g_cxl_ring.fd >= 0) {
        close(g_cxl_ring.fd);
        g_cxl_ring.fd = -1;
    }
    if (g_cxl_ring.rings != NULL) {
        zfree(g_cxl_ring.rings);
        g_cxl_ring.rings = NULL;
    }
    if (g_cxl_ring.processed != NULL) {
        zfree(g_cxl_ring.processed);
        g_cxl_ring.processed = NULL;
    }
    return C_ERR;
}

int cxlRingEnabled(void) {
    return g_cxl_ring.enabled;
}

void cxlRingBeforeSleep(void) {
    if (!g_cxl_ring.enabled) return;

    for (int i = 0; i < g_cxl_ring.ring_count; i++) {
        uint32_t cid = 0, len = 0;
        uint16_t type = 0, flags = 0;
        uint8_t *payload = NULL;
        int budget = 32768;
        while (budget-- > 0) {
            int rc = cxlRingQueueRecv(&g_cxl_ring.rings[i].q21, &cid, &type,
                                      &flags, &payload, &len);
            if (rc <= 0) break;
            cxlRingHandleRequest(i, cid, type, flags, payload, len);
            g_cxl_ring.processed[i]++;
            atomic_fetch_add_explicit(&g_cxl_ring.stats_requests,
                                      1U, memory_order_relaxed);
            atomic_fetch_add_explicit(&g_cxl_ring.stats_responses,
                                      1U, memory_order_relaxed);
            if ((g_cxl_ring.processed[i] % 20000ULL) == 0ULL) {
                unsigned head = atomic_load_explicit(&g_cxl_ring.rings[i].q21.q->head,
                                                     memory_order_relaxed);
                unsigned tail = atomic_load_explicit(&g_cxl_ring.rings[i].q21.q->tail,
                                                     memory_order_relaxed);
                serverLog(LL_NOTICE,
                          "cxl ring[%d]: processed %llu requests (head=%u tail=%u)",
                          i, g_cxl_ring.processed[i], head, tail);
            }
        }
    }
}

static int cxlRingCron(aeEventLoop *eventLoop, long long id, void *clientData) {
    UNUSED(eventLoop);
    UNUSED(id);
    UNUSED(clientData);
    if (!g_cxl_ring.enabled) return AE_NOMORE;
    cxlRingBeforeSleep();
    return 1;
}

void cxlRingShutdown(void) {
    if (!g_cxl_ring.enabled && g_cxl_ring.fd < 0) return;
    cxlRingWriteStats();
    if (g_cxl_ring.timer_id > 0 && server.el != NULL)
        aeDeleteTimeEvent(server.el, g_cxl_ring.timer_id);
    if (g_cxl_ring.mm != NULL && g_cxl_ring.mm != MAP_FAILED)
        munmap(g_cxl_ring.mm, g_cxl_ring.map_size);
    if (g_cxl_ring.fd >= 0)
        close(g_cxl_ring.fd);
    if (g_cxl_ring.rings != NULL)
        zfree(g_cxl_ring.rings);
    if (g_cxl_ring.processed != NULL)
        zfree(g_cxl_ring.processed);
    memset(&g_cxl_ring, 0, sizeof(g_cxl_ring));
    g_cxl_ring.fd = -1;
}
