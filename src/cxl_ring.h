/* Minimal shared-memory ring support for CXL-DSM shim elimination.
 * This is a lightweight SPSC ring that can poll requests from a
 * shared memory file (e.g., PCI resource2 of ivshmem) and flush
 * Redis replies back to the same ring.
 *
 * Configuration is provided via environment variables:
 *   CXL_RING_PATH      - path to mmap (e.g., /sys/bus/pci/devices/0000:00:02.0/resource2)
 *   CXL_RING_MAP_SIZE  - bytes to mmap (default: 128MB if unset)
 *
 * The protocol matches shim/cxl_shm.py (msg_type: 1=data, 2=close).
 */
#pragma once

#include "server.h"

int cxlRingInitFromEnv(void);
int cxlRingEnabled(void);
void cxlRingBeforeSleep(void);
void cxlRingShutdown(void);
