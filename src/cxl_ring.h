/* Research-only CXL shared-memory ring transport for Redis benchmarks.
 *
 * The layout intentionally mirrors the tdx-shm branch protocol:
 * each ring region contains q21 (client -> server) and q12
 * (server -> client), and each slot carries a fixed header followed by
 * a binary payload.
 */
#pragma once

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CXL_RING_MAGIC 0x31584c4353494452ULL /* "RDISCLX1" little endian */
#define CXL_RING_VERSION 1U
#define CXL_RING_SLOT_SIZE 4096U
#define CXL_RING_QUEUE_CAPACITY 1024U
#define CXL_RING_SLOT_PREFIX_SIZE 2U
#define CXL_RING_SLOT_HDR_SIZE 16U
#define CXL_RING_MSG_MAX (CXL_RING_SLOT_SIZE - CXL_RING_SLOT_PREFIX_SIZE)
#define CXL_RING_MAX_PAYLOAD (CXL_RING_MSG_MAX - CXL_RING_SLOT_HDR_SIZE)
#define CXL_RING_MAX_RINGS 512

#define CXL_RING_MSG_DATA 1U
#define CXL_RING_MSG_CLOSE 2U

#define CXL_RING_HEADER_FLAG_READY 0x00000001U

#define CXL_OP_GET 1U
#define CXL_OP_SET 2U
#define CXL_OP_DEL 3U
#define CXL_OP_SCAN 4U

#define CXL_STATUS_OK 0U
#define CXL_STATUS_MISS 1U
#define CXL_STATUS_ERR 2U

struct cxl_ring_queue {
    _Atomic uint32_t head;
    _Atomic uint32_t tail;
    uint32_t capacity;
    uint32_t slot_size;
    uint32_t data_offset;
    uint32_t reserved;
};

struct cxl_ring_header {
    uint64_t magic;
    uint32_t version;
    uint32_t flags;
    uint64_t total_size;
    struct cxl_ring_queue q12;
    struct cxl_ring_queue q21;
};

struct cxl_ring_queue_view {
    struct cxl_ring_queue *q;
    uint8_t *data;
};

struct cxl_ring_region {
    struct cxl_ring_header *hdr;
    struct cxl_ring_queue_view q12;
    struct cxl_ring_queue_view q21;
};

struct cxl_ring_msg_hdr {
    uint32_t cid;
    uint16_t type;
    uint16_t flags;
    uint32_t len;
    uint32_t reserved;
};

static inline size_t cxlRingAlignUp(size_t value, size_t alignment) {
    return (value + alignment - 1U) / alignment * alignment;
}

static inline size_t cxlRingDefaultRegionSize(void) {
    size_t header_size = cxlRingAlignUp(sizeof(struct cxl_ring_header), 64U);
    size_t queue_bytes = (size_t)CXL_RING_QUEUE_CAPACITY * (size_t)CXL_RING_SLOT_SIZE;
    return cxlRingAlignUp(header_size + 2U * queue_bytes, 4096U);
}

static inline uint32_t cxlRingNext(uint32_t value, uint32_t capacity) {
    return (value + 1U) % capacity;
}

static inline int cxlRingRegionInit(void *base, size_t size) {
    size_t header_size = cxlRingAlignUp(sizeof(struct cxl_ring_header), 64U);
    size_t queue_bytes = (size_t)CXL_RING_QUEUE_CAPACITY * (size_t)CXL_RING_SLOT_SIZE;
    size_t needed = header_size + 2U * queue_bytes;

    if (base == NULL || size < needed) return -1;
    memset(base, 0, needed);

    struct cxl_ring_header *hdr = (struct cxl_ring_header *)base;
    hdr->magic = CXL_RING_MAGIC;
    hdr->version = CXL_RING_VERSION;
    hdr->flags = 0U;
    hdr->total_size = (uint64_t)size;

    hdr->q12.capacity = CXL_RING_QUEUE_CAPACITY;
    hdr->q12.slot_size = CXL_RING_SLOT_SIZE;
    hdr->q12.data_offset = (uint32_t)header_size;

    hdr->q21.capacity = CXL_RING_QUEUE_CAPACITY;
    hdr->q21.slot_size = CXL_RING_SLOT_SIZE;
    hdr->q21.data_offset = (uint32_t)(header_size + queue_bytes);

    atomic_store_explicit(&hdr->q12.head, 0U, memory_order_relaxed);
    atomic_store_explicit(&hdr->q12.tail, 0U, memory_order_relaxed);
    atomic_store_explicit(&hdr->q21.head, 0U, memory_order_relaxed);
    atomic_store_explicit(&hdr->q21.tail, 0U, memory_order_relaxed);
    return 0;
}

static inline int cxlRingRegionAttach(void *base, size_t size,
                                      struct cxl_ring_region *out) {
    if (base == NULL || out == NULL) return -1;

    struct cxl_ring_header *hdr = (struct cxl_ring_header *)base;
    if (hdr->magic != CXL_RING_MAGIC || hdr->version != CXL_RING_VERSION) return -1;
    if (hdr->total_size == 0 || hdr->total_size > (uint64_t)size) return -1;
    if (hdr->q12.capacity != CXL_RING_QUEUE_CAPACITY ||
        hdr->q21.capacity != CXL_RING_QUEUE_CAPACITY) return -1;
    if (hdr->q12.slot_size != CXL_RING_SLOT_SIZE ||
        hdr->q21.slot_size != CXL_RING_SLOT_SIZE) return -1;

    size_t queue_bytes = (size_t)CXL_RING_QUEUE_CAPACITY * (size_t)CXL_RING_SLOT_SIZE;
    if ((size_t)hdr->q12.data_offset + queue_bytes > size) return -1;
    if ((size_t)hdr->q21.data_offset + queue_bytes > size) return -1;

    out->hdr = hdr;
    out->q12.q = &hdr->q12;
    out->q12.data = (uint8_t *)base + hdr->q12.data_offset;
    out->q21.q = &hdr->q21;
    out->q21.data = (uint8_t *)base + hdr->q21.data_offset;
    return 0;
}

static inline void cxlRingRegionReset(struct cxl_ring_region *region) {
    if (region == NULL || region->hdr == NULL) return;
    atomic_store_explicit(&region->hdr->q12.head, 0U, memory_order_relaxed);
    atomic_store_explicit(&region->hdr->q12.tail, 0U, memory_order_relaxed);
    atomic_store_explicit(&region->hdr->q21.head, 0U, memory_order_relaxed);
    atomic_store_explicit(&region->hdr->q21.tail, 0U, memory_order_relaxed);
}

static inline void cxlRingRegionSetReady(struct cxl_ring_region *region,
                                         int ready) {
    if (region == NULL || region->hdr == NULL) return;
    uint32_t flags = ready ? CXL_RING_HEADER_FLAG_READY : 0U;
    __atomic_store_n(&region->hdr->flags, flags, __ATOMIC_RELEASE);
}

static inline int cxlRingRegionIsReady(struct cxl_ring_region *region) {
    if (region == NULL || region->hdr == NULL) return 0;
    uint32_t flags = __atomic_load_n(&region->hdr->flags, __ATOMIC_ACQUIRE);
    return (flags & CXL_RING_HEADER_FLAG_READY) != 0U;
}

static inline int cxlRingQueueSend(struct cxl_ring_queue_view *tx,
                                   uint32_t cid, uint16_t type,
                                   uint16_t flags, const uint8_t *payload,
                                   uint32_t len) {
    if (tx == NULL || tx->q == NULL || tx->data == NULL) return -1;
    if (payload == NULL && len != 0U) return -1;
    if (len > CXL_RING_MAX_PAYLOAD) return -1;

    struct cxl_ring_queue *q = tx->q;
    uint32_t cap = q->capacity;
    if (cap == 0U) return -1;

    uint32_t head = atomic_load_explicit(&q->head, memory_order_acquire);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint32_t next = cxlRingNext(tail, cap);
    if (next == head) return 0;

    uint8_t *slot = tx->data + ((size_t)tail * q->slot_size);
    uint16_t msg_len = (uint16_t)(CXL_RING_SLOT_HDR_SIZE + len);
    memcpy(slot, &msg_len, sizeof(msg_len));

    struct cxl_ring_msg_hdr hdr;
    hdr.cid = cid;
    hdr.type = type;
    hdr.flags = flags;
    hdr.len = len;
    hdr.reserved = 0U;
    memcpy(slot + CXL_RING_SLOT_PREFIX_SIZE, &hdr, sizeof(hdr));
    if (len != 0U)
        memcpy(slot + CXL_RING_SLOT_PREFIX_SIZE + sizeof(hdr), payload, len);

    atomic_store_explicit(&q->tail, next, memory_order_release);
    return 1;
}

static inline int cxlRingQueueRecv(struct cxl_ring_queue_view *rx,
                                   uint32_t *cid, uint16_t *type,
                                   uint16_t *flags, uint8_t **payload,
                                   uint32_t *len) {
    if (rx == NULL || rx->q == NULL || rx->data == NULL) return -1;
    if (cid == NULL || type == NULL || flags == NULL ||
        payload == NULL || len == NULL) return -1;

    struct cxl_ring_queue *q = rx->q;
    uint32_t cap = q->capacity;
    if (cap == 0U) return -1;

    uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    if (head == tail) return 0;

    uint8_t *slot = rx->data + ((size_t)head * q->slot_size);
    uint16_t msg_len = 0;
    memcpy(&msg_len, slot, sizeof(msg_len));
    if (msg_len < sizeof(struct cxl_ring_msg_hdr) ||
        msg_len > CXL_RING_MSG_MAX) return -1;

    struct cxl_ring_msg_hdr hdr;
    memcpy(&hdr, slot + CXL_RING_SLOT_PREFIX_SIZE, sizeof(hdr));
    if (hdr.len > (uint32_t)(msg_len - sizeof(hdr))) return -1;
    if (hdr.len > CXL_RING_MAX_PAYLOAD) return -1;

    *cid = hdr.cid;
    *type = hdr.type;
    *flags = hdr.flags;
    *len = hdr.len;
    *payload = slot + CXL_RING_SLOT_PREFIX_SIZE + sizeof(hdr);

    atomic_store_explicit(&q->head, cxlRingNext(head, cap), memory_order_release);
    return 1;
}

int cxlRingInitFromEnv(void);
int cxlRingEnabled(void);
void cxlRingBeforeSleep(void);
void cxlRingShutdown(void);
