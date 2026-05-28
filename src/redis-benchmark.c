/* Redis benchmark utility.
 *
 * Copyright (c) 2009-Present, Redis Ltd.
 * All rights reserved.
 *
 * Licensed under your choice of (a) the Redis Source Available License 2.0
 * (RSALv2); or (b) the Server Side Public License v1 (SSPLv1); or (c) the
 * GNU Affero General Public License v3 (AGPLv3).
 */

#include "fmacros.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <limits.h>
#include <signal.h>
#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <fcntl.h>
#include <sched.h>
#include <strings.h>

#include <sdscompat.h> /* Use hiredis' sds compat header that maps sds calls to their hi_ variants */
#include <sds.h> /* Use hiredis sds. */
#include "ae.h"
#include <hiredis.h>
#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <hiredis_ssl.h>
#endif
#include "adlist.h"
#include "dict.h"
#include "zmalloc.h"
#include "atomicvar.h"
#include "crc16_slottable.h"
#include "hdr_histogram.h"
#include "cli_common.h"
#include "mt19937-64.h"
#include "cxl_ring.h"

#define UNUSED(V) ((void) V)
#define RANDPTR_INITIAL_SIZE 8
#define DEFAULT_LATENCY_PRECISION 3
#define MAX_LATENCY_PRECISION 4
#define MAX_THREADS 500
#define CLUSTER_SLOTS 16384
#define CONFIG_LATENCY_HISTOGRAM_MIN_VALUE 10L          /* >= 10 usecs */
#define CONFIG_LATENCY_HISTOGRAM_MAX_VALUE 3000000L          /* <= 3 secs(us precision) */
#define CONFIG_LATENCY_HISTOGRAM_INSTANT_MAX_VALUE 3000000L   /* <= 3 secs(us precision) */
#define SHOW_THROUGHPUT_INTERVAL 250  /* 250ms */
#define CXL_BENCH_DEFAULT_MAP_SIZE (1024ULL * 1024ULL * 1024ULL)
#define CXL_BENCH_ATTACH_TIMEOUT_US (30LL * 1000LL * 1000LL)
#define CXL_BENCH_ATTACH_MAX_TRIES 10000000
#ifndef C_OK
#define C_OK 0
#define C_ERR -1
#endif

#define CLIENT_GET_EVENTLOOP(c) \
    (c->thread_id >= 0 ? config.threads[c->thread_id]->el : config.el)

static int cxlBenchDebugEnabled(void) {
    static int initialized = 0;
    static int enabled = 0;
    if (!initialized) {
        const char *value = getenv("CXL_BENCH_DEBUG");
        enabled = value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
        initialized = 1;
    }
    return enabled;
}

static int redisGem5SeDontWaitEnabled(void) {
    const char *value = getenv("REDIS_GEM5_SE_DONT_WAIT");
    return value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
}

#define CXL_BENCH_DEBUGF(...) do { \
    if (cxlBenchDebugEnabled()) { \
        fprintf(stderr, __VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

enum {
    CXL_BENCH_MODE_NATIVE_SHM = 0,
    CXL_BENCH_MODE_DSM_TEE = 1
};

enum {
    CXL_YCSB_WORKLOAD_A = 0,
    CXL_YCSB_WORKLOAD_B,
    CXL_YCSB_WORKLOAD_C,
    CXL_YCSB_WORKLOAD_D,
    CXL_YCSB_WORKLOAD_E,
    CXL_YCSB_WORKLOAD_F
};

enum {
    CXL_YCSB_PHASE_LOAD = 0,
    CXL_YCSB_PHASE_RUN,
    CXL_YCSB_PHASE_LOAD_RUN
};

enum {
    CXL_YCSB_DIST_AUTO = 0,
    CXL_YCSB_DIST_UNIFORM,
    CXL_YCSB_DIST_ZIPFIAN,
    CXL_YCSB_DIST_LATEST
};

enum {
    YCSB_TRANSPORT_AUTO = 0,
    YCSB_TRANSPORT_TCP,
    YCSB_TRANSPORT_CXL
};

enum {
    CXL_YCSB_OP_READ = 0,
    CXL_YCSB_OP_UPDATE,
    CXL_YCSB_OP_INSERT,
    CXL_YCSB_OP_SCAN,
    CXL_YCSB_OP_RMW,
    CXL_YCSB_OP_MAX
};

struct benchmarkThread;
struct clusterNode;
struct redisConfig;

static struct config {
    aeEventLoop *el;
    cliConnInfo conn_info;
    const char *hostsocket;
    int tls;
    struct cliSSLconfig sslconfig;
    int numclients;
    redisAtomic int liveclients;
    int requests;
    redisAtomic int requests_issued;
    redisAtomic int requests_finished;
    redisAtomic int previous_requests_finished;
    int last_printed_bytes;
    long long previous_tick;
    int keysize;
    int datasize;
    int datasize_set;
    int randomkeys;
    int randomkeys_keyspacelen;
    int keepalive;
    int pipeline;
    long long start;
    long long totlatency;
    const char *title;
    list *clients;
    int quiet;
    int csv;
    int loop;
    int idlemode;
    sds input_dbnumstr;
    char *tests;
    int stdinarg; /* get last arg from stdin. (-x option) */
    int precision;
    int num_threads;
    int threads_use_main;
    struct benchmarkThread **threads;
    int cluster_mode;
    int cluster_node_count;
    struct clusterNode **cluster_nodes;
    struct redisConfig *redis_config;
    struct hdr_histogram* latency_histogram;
    struct hdr_histogram* current_sec_latency_histogram;
    redisAtomic int is_fetching_slots;
    redisAtomic int is_updating_slots;
    redisAtomic int slots_last_update;
    int enable_tracking;
    pthread_mutex_t liveclients_mutex;
    pthread_mutex_t is_updating_slots_mutex;
    int resp3; /* use RESP3 */
    int cxl_enabled;
    int cxl_mode;
    int cxl_paper_preset;
    char *cxl_ring_path;
    size_t cxl_ring_map_size;
    size_t cxl_ring_offset;
    size_t cxl_ring_region_base;
    size_t cxl_ring_region_size;
    int cxl_ring_count;
    int ycsb_enabled;
    int ycsb_transport;
    int ycsb_workload;
    int ycsb_phase;
    unsigned long long ycsb_record_count;
    unsigned long long ycsb_operation_count;
    unsigned long long ycsb_insert_start;
    int ycsb_insert_start_set;
    int ycsb_request_distribution;
    int ycsb_scan_length_distribution;
    int ycsb_max_scan_length;
    int ycsb_field_count;
    int ycsb_field_length;
    int ycsb_read_all_fields;
    unsigned long long ycsb_seed;
    char *ycsb_key_prefix;
    int ycsb_key_width;
    double ycsb_zipf_theta;
    int server_ready_timeout_ms;
    int gem5_client_id;
    int gem5_client_count;
    int gem5_client_sync_timeout_ms;
    int shutdown_server_after;
    char *gem5_client_sync_dir;
} config;

typedef struct _client {
    redisContext *context;
    sds obuf;
    char **randptr;         /* Pointers to :rand: strings inside the command buf */
    size_t randlen;         /* Number of pointers in client->randptr */
    size_t randfree;        /* Number of unused pointers in client->randptr */
    char **stagptr;         /* Pointers to slot hashtags (cluster mode only) */
    size_t staglen;         /* Number of pointers in client->stagptr */
    size_t stagfree;        /* Number of unused pointers in client->stagptr */
    size_t written;         /* Bytes of 'obuf' already written */
    long long start;        /* Start time of a request */
    long long latency;      /* Request latency */
    int pending;            /* Number of pending requests (replies to consume) */
    int prefix_pending;     /* If non-zero, number of pending prefix commands. Commands
                               such as auth and select are prefixed to the pipeline of
                               benchmark commands and discarded after the first send. */
    int prefixlen;          /* Size in bytes of the pending prefix commands */
    int thread_id;
    struct clusterNode *cluster_node;
    int slots_last_update;
} *client;

/* Threads. */

typedef struct benchmarkThread {
    int index;
    pthread_t thread;
    aeEventLoop *el;
} benchmarkThread;

/* Cluster. */
typedef struct clusterNode {
    char *ip;
    int port;
    sds name;
    int flags;
    sds replicate;  /* Master ID if node is a slave */
    int *slots;
    int slots_count;
    int *updated_slots;         /* Used by updateClusterSlotsConfiguration */
    int updated_slots_count;    /* Used by updateClusterSlotsConfiguration */
    int replicas_count;
    sds *migrating; /* An array of sds where even strings are slots and odd
                     * strings are the destination node IDs. */
    sds *importing; /* An array of sds where even strings are slots and odd
                     * strings are the source node IDs. */
    int migrating_count; /* Length of the migrating array (migrating slots*2) */
    int importing_count; /* Length of the importing array (importing slots*2) */
    struct redisConfig *redis_config;
} clusterNode;

typedef struct redisConfig {
    sds save;
    sds appendonly;
} redisConfig;

/* Prototypes */
static void writeHandler(aeEventLoop *el, int fd, void *privdata, int mask);
static void createMissingClients(client c);
static benchmarkThread *createBenchmarkThread(int index);
static void freeBenchmarkThread(benchmarkThread *thread);
static void freeBenchmarkThreads(void);
static void *execBenchmarkThread(void *ptr);
static clusterNode *createClusterNode(char *ip, int port);
static redisConfig *getRedisConfig(const char *ip, int port,
                                   const char *hostsocket);
static redisContext *getRedisContext(const char *ip, int port,
                                     const char *hostsocket);
static void freeRedisConfig(redisConfig *cfg);
static int fetchClusterSlotsConfiguration(client c);
static void updateClusterSlotsConfiguration(void);
static int cxlBenchParseSize(const char *arg, size_t *out);
static int cxlBenchParseMode(const char *mode);
static int cxlYcsbParseWorkload(const char *workload);
static int cxlYcsbParsePhase(const char *phase);
static int cxlYcsbParseDistribution(const char *dist, int allow_latest);
static int cxlYcsbParseUInt64(const char *arg, unsigned long long *out);
static int cxlBenchmarkMain(int argc, char **argv);
int showThroughput(struct aeEventLoop *eventLoop, long long id,
                   void *clientData);

/* Dict callbacks */
static uint64_t dictSdsHash(const void *key);
static int dictSdsKeyCompare(dictCmpCache *cache, const void *key1, const void *key2);

/* Implementation */
static long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}

static long long mstime(void) {
    return ustime()/1000;
}

static uint64_t dictSdsHash(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}

static int dictSdsKeyCompare(dictCmpCache *cache, const void *key1, const void *key2)
{
    int l1,l2;
    UNUSED(cache);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2) return 0;
    return memcmp(key1, key2, l1) == 0;
}

static redisContext *getRedisContext(const char *ip, int port,
                                     const char *hostsocket)
{
    redisContext *ctx = NULL;
    redisReply *reply =  NULL;
    char last_err[256] = "";
    long long deadline = ustime() +
        (long long)config.server_ready_timeout_ms * 1000LL;

    while (1) {
        if (hostsocket == NULL)
            ctx = redisConnect(ip, port);
        else
            ctx = redisConnectUnix(hostsocket);
        if (ctx != NULL && !ctx->err) break;

        snprintf(last_err, sizeof(last_err), "%s",
                 ctx != NULL ? ctx->errstr : "");
        if (ctx != NULL) {
            redisFree(ctx);
            ctx = NULL;
        }
        if (config.server_ready_timeout_ms <= 0 || ustime() >= deadline)
            break;
        sched_yield();
    }

    if (ctx == NULL || ctx->err) {
        fprintf(stderr,"Could not connect to Redis at ");
        char *err = (ctx != NULL ? ctx->errstr : last_err);
        if (hostsocket == NULL)
            fprintf(stderr,"%s:%d: %s\n",ip,port,err);
        else
            fprintf(stderr,"%s: %s\n",hostsocket,err);
        goto cleanup;
    }
    if (config.tls==1) {
        const char *err = NULL;
        if (cliSecureConnection(ctx, config.sslconfig, &err) == REDIS_ERR && err) {
            fprintf(stderr, "Could not negotiate a TLS connection: %s\n", err);
            goto cleanup;
        }
    }
    if (config.conn_info.auth == NULL)
        return ctx;
    if (config.conn_info.user == NULL)
        reply = redisCommand(ctx,"AUTH %s", config.conn_info.auth);
    else
        reply = redisCommand(ctx,"AUTH %s %s", config.conn_info.user, config.conn_info.auth);
    if (reply != NULL) {
        if (reply->type == REDIS_REPLY_ERROR) {
            if (hostsocket == NULL)
                fprintf(stderr, "Node %s:%d replied with error:\n%s\n", ip, port, reply->str);
            else
                fprintf(stderr, "Node %s replied with error:\n%s\n", hostsocket, reply->str);
            freeReplyObject(reply);
            redisFree(ctx);
            exit(1);
        }
        freeReplyObject(reply);
        return ctx;
    }
    fprintf(stderr, "ERROR: failed to fetch reply from ");
    if (hostsocket == NULL)
        fprintf(stderr, "%s:%d\n", ip, port);
    else
        fprintf(stderr, "%s\n", hostsocket);
cleanup:
    freeReplyObject(reply);
    if (ctx != NULL) redisFree(ctx);
    return NULL;
}



static redisConfig *getRedisConfig(const char *ip, int port,
                                   const char *hostsocket)
{
    redisConfig *cfg = zcalloc(sizeof(*cfg));
    if (!cfg) return NULL;
    redisContext *c = NULL;
    redisReply *reply = NULL, *sub_reply = NULL;
    c = getRedisContext(ip, port, hostsocket);
    if (c == NULL) {
        freeRedisConfig(cfg);
        exit(1);
    }
    redisAppendCommand(c, "CONFIG GET %s", "save");
    redisAppendCommand(c, "CONFIG GET %s", "appendonly");
    int abort_test = 0;
    int i = 0;
    void *r = NULL;
    for (; i < 2; i++) {
        int res = redisGetReply(c, &r);
        if (reply) freeReplyObject(reply);
        reply = res == REDIS_OK ? ((redisReply *) r) : NULL;
        if (res != REDIS_OK || !r) goto fail;
        if (reply->type == REDIS_REPLY_ERROR) {
            goto fail;
        }
        if (reply->type != REDIS_REPLY_ARRAY || reply->elements < 2) goto fail;
        sub_reply = reply->element[1];
        char *value = sub_reply->str;
        if (!value) value = "";
        switch (i) {
        case 0: cfg->save = sdsnew(value); break;
        case 1: cfg->appendonly = sdsnew(value); break;
        }
    }
    freeReplyObject(reply);
    redisFree(c);
    return cfg;
fail:
    if (reply && reply->type == REDIS_REPLY_ERROR &&
        !strncmp(reply->str,"NOAUTH",6)) {
        if (hostsocket == NULL)
            fprintf(stderr, "Node %s:%d replied with error:\n%s\n", ip, port, reply->str);
        else
            fprintf(stderr, "Node %s replied with error:\n%s\n", hostsocket, reply->str);
        abort_test = 1;
    }
    freeReplyObject(reply);
    redisFree(c);
    freeRedisConfig(cfg);
    if (abort_test) exit(1);
    return NULL;
}
static void freeRedisConfig(redisConfig *cfg) {
    if (cfg->save) sdsfree(cfg->save);
    if (cfg->appendonly) sdsfree(cfg->appendonly);
    zfree(cfg);
}

static void freeClient(client c) {
    aeEventLoop *el = CLIENT_GET_EVENTLOOP(c);
    listNode *ln;
    aeDeleteFileEvent(el,c->context->fd,AE_WRITABLE);
    aeDeleteFileEvent(el,c->context->fd,AE_READABLE);
    if (c->thread_id >= 0) {
        int requests_finished = 0;
        atomicGet(config.requests_finished, requests_finished);
        if (requests_finished >= config.requests) {
            aeStop(el);
        }
    }
    redisFree(c->context);
    sdsfree(c->obuf);
    zfree(c->randptr);
    zfree(c->stagptr);
    zfree(c);
    if (config.num_threads) pthread_mutex_lock(&(config.liveclients_mutex));
    config.liveclients--;
    ln = listSearchKey(config.clients,c);
    assert(ln != NULL);
    listDelNode(config.clients,ln);
    if (config.num_threads) pthread_mutex_unlock(&(config.liveclients_mutex));
}

static void freeAllClients(void) {
    listNode *ln = config.clients->head, *next;

    while(ln) {
        next = ln->next;
        freeClient(ln->value);
        ln = next;
    }
}

static void resetClient(client c) {
    aeEventLoop *el = CLIENT_GET_EVENTLOOP(c);
    aeDeleteFileEvent(el,c->context->fd,AE_WRITABLE);
    aeDeleteFileEvent(el,c->context->fd,AE_READABLE);
    aeCreateFileEvent(el,c->context->fd,AE_WRITABLE,writeHandler,c);
    c->written = 0;
    c->pending = config.pipeline;
}

static void randomizeClientKey(client c) {
    size_t i;

    for (i = 0; i < c->randlen; i++) {
        char *p = c->randptr[i]+11;
        size_t r = 0;
        if (config.randomkeys_keyspacelen != 0)
            r = random() % config.randomkeys_keyspacelen;
        size_t j;

        for (j = 0; j < 12; j++) {
            *p = '0'+r%10;
            r/=10;
            p--;
        }
    }
}

static void setClusterKeyHashTag(client c) {
    assert(c->thread_id >= 0);
    clusterNode *node = c->cluster_node;
    assert(node);
    int is_updating_slots = 0;
    atomicGet(config.is_updating_slots, is_updating_slots);
    /* If updateClusterSlotsConfiguration is updating the slots array,
     * call updateClusterSlotsConfiguration is order to block the thread
     * since the mutex is locked. When the slots will be updated by the
     * thread that's actually performing the update, the execution of
     * updateClusterSlotsConfiguration won't actually do anything, since
     * the updated_slots_count array will be already NULL. */
    if (is_updating_slots) updateClusterSlotsConfiguration();
    int slot = node->slots[rand() % node->slots_count];
    const char *tag = crc16_slot_table[slot];
    int taglen = strlen(tag);
    size_t i;
    for (i = 0; i < c->staglen; i++) {
        char *p = c->stagptr[i] + 1;
        p[0] = tag[0];
        p[1] = (taglen >= 2 ? tag[1] : '}');
        p[2] = (taglen == 3 ? tag[2] : '}');
    }
}

static void clientDone(client c) {
    int requests_finished = 0;
    atomicGet(config.requests_finished, requests_finished);
    if (requests_finished >= config.requests) {
        freeClient(c);
        if (!config.num_threads && config.el) aeStop(config.el);
        return;
    }
    if (config.keepalive) {
        resetClient(c);
    } else {
        if (config.num_threads) pthread_mutex_lock(&(config.liveclients_mutex));
        config.liveclients--;
        createMissingClients(c);
        config.liveclients++;
        if (config.num_threads)
            pthread_mutex_unlock(&(config.liveclients_mutex));
        freeClient(c);
    }
}

REDIS_NO_SANITIZE_MSAN("memory")
static void readHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    client c = privdata;
    void *reply = NULL;
    UNUSED(el);
    UNUSED(fd);
    UNUSED(mask);

    /* Calculate latency only for the first read event. This means that the
     * server already sent the reply and we need to parse it. Parsing overhead
     * is not part of the latency, so calculate it only once, here. */
    if (c->latency < 0) c->latency = ustime()-(c->start);

    if (redisBufferRead(c->context) != REDIS_OK) {
        fprintf(stderr,"Error: %s\n",c->context->errstr);
        exit(1);
    } else {
        while(c->pending) {
            if (redisGetReply(c->context,&reply) != REDIS_OK) {
                fprintf(stderr,"Error: %s\n",c->context->errstr);
                exit(1);
            }
            if (reply != NULL) {
                if (reply == (void*)REDIS_REPLY_ERROR) {
                    fprintf(stderr,"Unexpected error reply, exiting...\n");
                    exit(1);
                }
                redisReply *r = reply;
                if (r->type == REDIS_REPLY_ERROR) {
                    /* Try to update slots configuration if reply error is
                    * MOVED/ASK/CLUSTERDOWN and the key(s) used by the command
                    * contain(s) the slot hash tag.
                    * If the error is not topology-update related then we
                    * immediately exit to avoid false results. */
                    if (c->cluster_node && c->staglen) {
                        int fetch_slots = 0, do_wait = 0;
                        if (!strncmp(r->str,"MOVED",5) || !strncmp(r->str,"ASK",3))
                            fetch_slots = 1;
                        else if (!strncmp(r->str,"CLUSTERDOWN",11)) {
                            /* Usually the cluster is able to recover itself after
                            * a CLUSTERDOWN error, so try to sleep one second
                            * before requesting the new configuration. */
                            fetch_slots = 1;
                            do_wait = 1;
                            fprintf(stderr, "Error from server %s:%d: %s.\n",
                                    c->cluster_node->ip,
                                    c->cluster_node->port,
                                    r->str);
                        }
                        if (do_wait) sleep(1);
                        if (fetch_slots && !fetchClusterSlotsConfiguration(c))
                            exit(1);
                    } else {
                        if (c->cluster_node) {
                            fprintf(stderr, "Error from server %s:%d: %s\n",
                                 c->cluster_node->ip,
                                 c->cluster_node->port,
                                 r->str);
                        } else fprintf(stderr, "Error from server: %s\n", r->str);
                        exit(1);
                    }
                }

                freeReplyObject(reply);
                /* This is an OK for prefix commands such as auth and select.*/
                if (c->prefix_pending > 0) {
                    c->prefix_pending--;
                    c->pending--;
                    /* Discard prefix commands on first response.*/
                    if (c->prefixlen > 0) {
                        size_t j;
                        sdsrange(c->obuf, c->prefixlen, -1);
                        /* We also need to fix the pointers to the strings
                        * we need to randomize. */
                        for (j = 0; j < c->randlen; j++)
                            c->randptr[j] -= c->prefixlen;
                        /* Fix the pointers to the slot hash tags */
                        for (j = 0; j < c->staglen; j++)
                            c->stagptr[j] -= c->prefixlen;
                        c->prefixlen = 0;
                    }
                    continue;
                }
                int requests_finished = 0;
                atomicGetIncr(config.requests_finished, requests_finished, 1);
                if (requests_finished < config.requests){
                        if (config.num_threads == 0) {
                            hdr_record_value(
                            config.latency_histogram,  // Histogram to record to
                            (long)c->latency<=CONFIG_LATENCY_HISTOGRAM_MAX_VALUE ? (long)c->latency : CONFIG_LATENCY_HISTOGRAM_MAX_VALUE);  // Value to record
                            hdr_record_value(
                            config.current_sec_latency_histogram,  // Histogram to record to
                            (long)c->latency<=CONFIG_LATENCY_HISTOGRAM_INSTANT_MAX_VALUE ? (long)c->latency : CONFIG_LATENCY_HISTOGRAM_INSTANT_MAX_VALUE);  // Value to record
                        } else {
                            hdr_record_value_atomic(
                            config.latency_histogram,  // Histogram to record to
                            (long)c->latency<=CONFIG_LATENCY_HISTOGRAM_MAX_VALUE ? (long)c->latency : CONFIG_LATENCY_HISTOGRAM_MAX_VALUE);  // Value to record
                            hdr_record_value_atomic(
                            config.current_sec_latency_histogram,  // Histogram to record to
                            (long)c->latency<=CONFIG_LATENCY_HISTOGRAM_INSTANT_MAX_VALUE ? (long)c->latency : CONFIG_LATENCY_HISTOGRAM_INSTANT_MAX_VALUE);  // Value to record
                        }
                }
                c->pending--;
                if (c->pending == 0) {
                    clientDone(c);
                    break;
                }
            } else {
                break;
            }
        }
    }
}

static void writeHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    client c = privdata;
    UNUSED(el);
    UNUSED(fd);
    UNUSED(mask);

    /* Initialize request when nothing was written. */
    if (c->written == 0) {
        /* Enforce upper bound to number of requests. */
        int requests_issued = 0;
        atomicGetIncr(config.requests_issued, requests_issued, config.pipeline);
        if (requests_issued >= config.requests) {
            return;
        }

        /* Really initialize: randomize keys and set start time. */
        if (config.randomkeys) randomizeClientKey(c);
        if (config.cluster_mode && c->staglen > 0) setClusterKeyHashTag(c);
        atomicGet(config.slots_last_update, c->slots_last_update);
        c->start = ustime();
        c->latency = -1;
    }
    const ssize_t buflen = sdslen(c->obuf);
    const ssize_t writeLen = buflen-c->written;
    if (writeLen > 0) {
        void *ptr = c->obuf+c->written;
        while(1) {
            /* Optimistically try to write before checking if the file descriptor
             * is actually writable. At worst we get EAGAIN. */
            const ssize_t nwritten = cliWriteConn(c->context,ptr,writeLen);
            if (nwritten != writeLen) {
                if (nwritten == -1 && errno != EAGAIN) {
                    if (errno != EPIPE)
                        fprintf(stderr, "Error writing to the server: %s\n", strerror(errno));
                    freeClient(c);
                    return;
                } else if (nwritten > 0) {
                    c->written += nwritten;
                    return;
                }
            } else {
                aeDeleteFileEvent(el,c->context->fd,AE_WRITABLE);
                aeCreateFileEvent(el,c->context->fd,AE_READABLE,readHandler,c);
                return;
            }
        }
    }
}

/* Create a benchmark client, configured to send the command passed as 'cmd' of
 * 'len' bytes.
 *
 * The command is copied N times in the client output buffer (that is reused
 * again and again to send the request to the server) accordingly to the configured
 * pipeline size.
 *
 * Also an initial SELECT command is prepended in order to make sure the right
 * database is selected, if needed. The initial SELECT will be discarded as soon
 * as the first reply is received.
 *
 * To create a client from scratch, the 'from' pointer is set to NULL. If instead
 * we want to create a client using another client as reference, the 'from' pointer
 * points to the client to use as reference. In such a case the following
 * information is take from the 'from' client:
 *
 * 1) The command line to use.
 * 2) The offsets of the __rand_int__ elements inside the command line, used
 *    for arguments randomization.
 *
 * Even when cloning another client, prefix commands are applied if needed.*/
static client createClient(char *cmd, size_t len, client from, int thread_id) {
    int j;
    int is_cluster_client = (config.cluster_mode && thread_id >= 0);
    client c = zmalloc(sizeof(struct _client));

    const char *ip = NULL;
    int port = 0;
    c->cluster_node = NULL;
    if (config.hostsocket == NULL || is_cluster_client) {
        if (!is_cluster_client) {
            ip = config.conn_info.hostip;
            port = config.conn_info.hostport;
        } else {
            int node_idx = 0;
            if (config.num_threads < config.cluster_node_count)
                node_idx = config.liveclients % config.cluster_node_count;
            else
                node_idx = thread_id % config.cluster_node_count;
            clusterNode *node = config.cluster_nodes[node_idx];
            assert(node != NULL);
            ip = (const char *) node->ip;
            port = node->port;
            c->cluster_node = node;
        }
        c->context = redisConnectNonBlock(ip,port);
    } else {
        c->context = redisConnectUnixNonBlock(config.hostsocket);
    }
    if (c->context->err) {
        fprintf(stderr,"Could not connect to Redis at ");
        if (config.hostsocket == NULL || is_cluster_client)
            fprintf(stderr,"%s:%d: %s\n",ip,port,c->context->errstr);
        else
            fprintf(stderr,"%s: %s\n",config.hostsocket,c->context->errstr);
        exit(1);
    }
    if (config.tls==1) {
        const char *err = NULL;
        if (cliSecureConnection(c->context, config.sslconfig, &err) == REDIS_ERR && err) {
            fprintf(stderr, "Could not negotiate a TLS connection: %s\n", err);
            exit(1);
        }
    }
    c->thread_id = thread_id;
    /* Suppress hiredis cleanup of unused buffers for max speed. */
    c->context->reader->maxbuf = 0;

    /* Build the request buffer:
     * Queue N requests accordingly to the pipeline size, or simply clone
     * the example client buffer. */
    c->obuf = sdsempty();
    /* Prefix the request buffer with AUTH and/or SELECT commands, if applicable.
     * These commands are discarded after the first response, so if the client is
     * reused the commands will not be used again. */
    c->prefix_pending = 0;
    if (config.conn_info.auth) {
        char *buf = NULL;
        int len;
        if (config.conn_info.user == NULL)
            len = redisFormatCommand(&buf, "AUTH %s", config.conn_info.auth);
        else
            len = redisFormatCommand(&buf, "AUTH %s %s",
                                     config.conn_info.user, config.conn_info.auth);
        c->obuf = sdscatlen(c->obuf, buf, len);
        free(buf);
        c->prefix_pending++;
    }

    if (config.enable_tracking) {
        char *buf = NULL;
        int len = redisFormatCommand(&buf, "CLIENT TRACKING on");
        c->obuf = sdscatlen(c->obuf, buf, len);
        free(buf);
        c->prefix_pending++;
    }

    /* If a DB number different than zero is selected, prefix our request
     * buffer with the SELECT command, that will be discarded the first
     * time the replies are received, so if the client is reused the
     * SELECT command will not be used again. */
    if (config.conn_info.input_dbnum != 0 && !is_cluster_client) {
        c->obuf = sdscatprintf(c->obuf,"*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n",
            (int)sdslen(config.input_dbnumstr),config.input_dbnumstr);
        c->prefix_pending++;
    }

    if (config.resp3) {
        char *buf = NULL;
        int len = redisFormatCommand(&buf, "HELLO 3");
        c->obuf = sdscatlen(c->obuf, buf, len);
        free(buf);
        c->prefix_pending++;
    }

    c->prefixlen = sdslen(c->obuf);
    /* Append the request itself. */
    if (from) {
        c->obuf = sdscatlen(c->obuf,
            from->obuf+from->prefixlen,
            sdslen(from->obuf)-from->prefixlen);
    } else {
        for (j = 0; j < config.pipeline; j++)
            c->obuf = sdscatlen(c->obuf,cmd,len);
    }

    c->written = 0;
    c->pending = config.pipeline+c->prefix_pending;
    c->randptr = NULL;
    c->randlen = 0;
    c->stagptr = NULL;
    c->staglen = 0;

    /* Find substrings in the output buffer that need to be randomized. */
    if (config.randomkeys) {
        if (from) {
            c->randlen = from->randlen;
            c->randfree = 0;
            c->randptr = zmalloc(sizeof(char*)*c->randlen);
            /* copy the offsets. */
            for (j = 0; j < (int)c->randlen; j++) {
                c->randptr[j] = c->obuf + (from->randptr[j]-from->obuf);
                /* Adjust for the different select prefix length. */
                c->randptr[j] += c->prefixlen - from->prefixlen;
            }
        } else {
            char *p = c->obuf;

            c->randlen = 0;
            c->randfree = RANDPTR_INITIAL_SIZE;
            c->randptr = zmalloc(sizeof(char*)*c->randfree);
            while ((p = strstr(p,"__rand_int__")) != NULL) {
                if (c->randfree == 0) {
                    c->randptr = zrealloc(c->randptr,sizeof(char*)*c->randlen*2);
                    c->randfree += c->randlen;
                }
                c->randptr[c->randlen++] = p;
                c->randfree--;
                p += 12; /* 12 is strlen("__rand_int__). */
            }
        }
    }
    /* If cluster mode is enabled, set slot hashtags pointers. */
    if (config.cluster_mode) {
        if (from) {
            c->staglen = from->staglen;
            c->stagfree = 0;
            c->stagptr = zmalloc(sizeof(char*)*c->staglen);
            /* copy the offsets. */
            for (j = 0; j < (int)c->staglen; j++) {
                c->stagptr[j] = c->obuf + (from->stagptr[j]-from->obuf);
                /* Adjust for the different select prefix length. */
                c->stagptr[j] += c->prefixlen - from->prefixlen;
            }
        } else {
            char *p = c->obuf;

            c->staglen = 0;
            c->stagfree = RANDPTR_INITIAL_SIZE;
            c->stagptr = zmalloc(sizeof(char*)*c->stagfree);
            while ((p = strstr(p,"{tag}")) != NULL) {
                if (c->stagfree == 0) {
                    c->stagptr = zrealloc(c->stagptr,
                                          sizeof(char*) * c->staglen*2);
                    c->stagfree += c->staglen;
                }
                c->stagptr[c->staglen++] = p;
                c->stagfree--;
                p += 5; /* 5 is strlen("{tag}"). */
            }
        }
    }
    aeEventLoop *el = NULL;
    if (thread_id < 0) el = config.el;
    else {
        benchmarkThread *thread = config.threads[thread_id];
        el = thread->el;
    }
    if (config.idlemode == 0)
        aeCreateFileEvent(el,c->context->fd,AE_WRITABLE,writeHandler,c);
    else
        /* In idle mode, clients still need to register readHandler for catching errors */
        aeCreateFileEvent(el,c->context->fd,AE_READABLE,readHandler,c);

    listAddNodeTail(config.clients,c);
    atomicIncr(config.liveclients, 1);
    atomicGet(config.slots_last_update, c->slots_last_update);
    return c;
}

static void createMissingClients(client c) {
    int n = 0;
    while(config.liveclients < config.numclients) {
        int thread_id = -1;
        if (config.num_threads)
            thread_id = config.liveclients % config.num_threads;
        createClient(NULL,0,c,thread_id);

        /* Listen backlog is quite limited on most systems */
        if (++n > 64) {
            usleep(50000);
            n = 0;
        }
    }
}

static void showLatencyReport(void) {

    const float reqpersec = (float)config.requests_finished/((float)config.totlatency/1000.0f);
    const float p0 = ((float) hdr_min(config.latency_histogram))/1000.0f;
    const float p50 = hdr_value_at_percentile(config.latency_histogram, 50.0 )/1000.0f;
    const float p95 = hdr_value_at_percentile(config.latency_histogram, 95.0 )/1000.0f;
    const float p99 = hdr_value_at_percentile(config.latency_histogram, 99.0 )/1000.0f;
    const float p100 = ((float) hdr_max(config.latency_histogram))/1000.0f;
    const float avg = hdr_mean(config.latency_histogram)/1000.0f;

    if (!config.quiet && !config.csv) {
        printf("%*s\r", config.last_printed_bytes, " "); // ensure there is a clean line
        printf("====== %s ======\n", config.title);
        printf("  %d requests completed in %.2f seconds\n", config.requests_finished,
            (float)config.totlatency/1000);
        printf("  %d parallel clients\n", config.numclients);
        printf("  %d bytes payload\n", config.datasize);
        printf("  keep alive: %d\n", config.keepalive);
        if (config.cluster_mode) {
            printf("  cluster mode: yes (%d masters)\n",
                   config.cluster_node_count);
            int m ;
            for (m = 0; m < config.cluster_node_count; m++) {
                clusterNode *node =  config.cluster_nodes[m];
                redisConfig *cfg = node->redis_config;
                if (cfg == NULL) continue;
                printf("  node [%d] configuration:\n",m );
                printf("    save: %s\n",
                    sdslen(cfg->save) ? cfg->save : "NONE");
                printf("    appendonly: %s\n", cfg->appendonly);
            }
        } else {
            if (config.redis_config) {
                printf("  host configuration \"save\": %s\n",
                       config.redis_config->save);
                printf("  host configuration \"appendonly\": %s\n",
                       config.redis_config->appendonly);
            }
        }
        printf("  multi-thread: %s\n", (config.num_threads ? "yes" : "no"));
        if (config.num_threads)
            printf("  threads: %d\n", config.num_threads);

        printf("\n");
        printf("Latency by percentile distribution:\n");
        struct hdr_iter iter;
        long long previous_cumulative_count = -1;
        const long long total_count = config.latency_histogram->total_count;
        hdr_iter_percentile_init(&iter, config.latency_histogram, 1);
        struct hdr_iter_percentiles *percentiles = &iter.specifics.percentiles;
        while (hdr_iter_next(&iter))
        {
            const double value = iter.highest_equivalent_value / 1000.0f;
            const double percentile = percentiles->percentile;
            const long long cumulative_count = iter.cumulative_count;
            if( previous_cumulative_count != cumulative_count || cumulative_count == total_count ){
                printf("%3.3f%% <= %.3f milliseconds (cumulative count %lld)\n", percentile, value, cumulative_count);
            }
            previous_cumulative_count = cumulative_count;
        }
        printf("\n");
        printf("Cumulative distribution of latencies:\n");
        previous_cumulative_count = -1;
        hdr_iter_linear_init(&iter, config.latency_histogram, 100);
        while (hdr_iter_next(&iter))
        {
            const double value = iter.highest_equivalent_value / 1000.0f;
            const long long cumulative_count = iter.cumulative_count;
            const double percentile = ((double)cumulative_count/(double)total_count)*100.0;
            if( previous_cumulative_count != cumulative_count || cumulative_count == total_count ){
                printf("%3.3f%% <= %.3f milliseconds (cumulative count %lld)\n", percentile, value, cumulative_count);
            }
            /* After the 2 milliseconds latency to have percentages split
             * by decimals will just add a lot of noise to the output. */
            if(iter.highest_equivalent_value > 2000){
                hdr_iter_linear_set_value_units_per_bucket(&iter,1000);
            }
            previous_cumulative_count = cumulative_count;
        }
        printf("\n");
        printf("Summary:\n");
        printf("  throughput summary: %.2f requests per second\n", reqpersec);
        printf("  latency summary (msec):\n");
        printf("    %9s %9s %9s %9s %9s %9s\n", "avg", "min", "p50", "p95", "p99", "max");
        printf("    %9.3f %9.3f %9.3f %9.3f %9.3f %9.3f\n", avg, p0, p50, p95, p99, p100);
    } else if (config.csv) {
        printf("\"%s\",\"%.2f\",\"%.3f\",\"%.3f\",\"%.3f\",\"%.3f\",\"%.3f\",\"%.3f\"\n", config.title, reqpersec, avg, p0, p50, p95, p99, p100);
    } else {
        printf("%*s\r", config.last_printed_bytes, " "); // ensure there is a clean line
        printf("%s: %.2f requests per second, p50=%.3f msec\n", config.title, reqpersec, p50);
    }
}

static void initBenchmarkThreads(void) {
    int i;
    if (config.threads) freeBenchmarkThreads();
    config.threads = zmalloc(config.num_threads * sizeof(benchmarkThread*));
    for (i = 0; i < config.num_threads; i++) {
        benchmarkThread *thread = createBenchmarkThread(i);
        config.threads[i] = thread;
    }
}

static void startBenchmarkThreads(void) {
    int i;
    int first_pthread = config.threads_use_main ? 1 : 0;
    for (i = first_pthread; i < config.num_threads; i++) {
        benchmarkThread *t = config.threads[i];
        if (pthread_create(&(t->thread), NULL, execBenchmarkThread, t)){
            fprintf(stderr, "FATAL: Failed to start thread %d.\n", i);
            exit(1);
        }
    }
    if (config.threads_use_main && config.num_threads > 0)
        execBenchmarkThread(config.threads[0]);
    for (i = first_pthread; i < config.num_threads; i++)
        pthread_join(config.threads[i]->thread, NULL);
}

static void benchmark(const char *title, char *cmd, int len) {
    client c;

    config.title = title;
    config.requests_issued = 0;
    config.requests_finished = 0;
    config.previous_requests_finished = 0;
    config.last_printed_bytes = 0;
    hdr_init(
        CONFIG_LATENCY_HISTOGRAM_MIN_VALUE,  // Minimum value
        CONFIG_LATENCY_HISTOGRAM_MAX_VALUE,  // Maximum value
        config.precision,  // Number of significant figures
        &config.latency_histogram);  // Pointer to initialise
    hdr_init(
        CONFIG_LATENCY_HISTOGRAM_MIN_VALUE,  // Minimum value
        CONFIG_LATENCY_HISTOGRAM_INSTANT_MAX_VALUE,  // Maximum value
        config.precision,  // Number of significant figures
        &config.current_sec_latency_histogram);  // Pointer to initialise

    if (config.num_threads) initBenchmarkThreads();

    int thread_id = config.num_threads > 0 ? 0 : -1;
    c = createClient(cmd,len,NULL,thread_id);
    createMissingClients(c);

    config.start = mstime();
    if (!config.num_threads) aeMain(config.el);
    else startBenchmarkThreads();
    config.totlatency = mstime()-config.start;

    showLatencyReport();
    freeAllClients();
    if (config.threads) freeBenchmarkThreads();
    if (config.current_sec_latency_histogram) hdr_close(config.current_sec_latency_histogram);
    if (config.latency_histogram) hdr_close(config.latency_histogram);

}

/* Thread functions. */

static benchmarkThread *createBenchmarkThread(int index) {
    benchmarkThread *thread = zmalloc(sizeof(*thread));
    if (thread == NULL) return NULL;
    thread->index = index;
    thread->el = aeCreateEventLoop(1024*10);
    if (redisGem5SeDontWaitEnabled())
        aeSetDontWait(thread->el, 1);
    aeCreateTimeEvent(thread->el,1,showThroughput,(void *)thread,NULL);
    return thread;
}

static void freeBenchmarkThread(benchmarkThread *thread) {
    if (thread->el) aeDeleteEventLoop(thread->el);
    zfree(thread);
}

static void freeBenchmarkThreads(void) {
    int i = 0;
    for (; i < config.num_threads; i++) {
        benchmarkThread *thread = config.threads[i];
        if (thread) freeBenchmarkThread(thread);
    }
    zfree(config.threads);
    config.threads = NULL;
}

static void *execBenchmarkThread(void *ptr) {
    benchmarkThread *thread = (benchmarkThread *) ptr;
    aeMain(thread->el);
    return NULL;
}

/* Cluster helper functions. */

static clusterNode *createClusterNode(char *ip, int port) {
    clusterNode *node = zmalloc(sizeof(*node));
    if (!node) return NULL;
    node->ip = ip;
    node->port = port;
    node->name = NULL;
    node->flags = 0;
    node->replicate = NULL;
    node->replicas_count = 0;
    node->slots = zmalloc(CLUSTER_SLOTS * sizeof(int));
    node->slots_count = 0;
    node->updated_slots = NULL;
    node->updated_slots_count = 0;
    node->migrating = NULL;
    node->importing = NULL;
    node->migrating_count = 0;
    node->importing_count = 0;
    node->redis_config = NULL;
    return node;
}

static void freeClusterNode(clusterNode *node) {
    int i;
    if (node->name) sdsfree(node->name);
    if (node->replicate) sdsfree(node->replicate);
    if (node->migrating != NULL) {
        for (i = 0; i < node->migrating_count; i++) sdsfree(node->migrating[i]);
        zfree(node->migrating);
    }
    if (node->importing != NULL) {
        for (i = 0; i < node->importing_count; i++) sdsfree(node->importing[i]);
        zfree(node->importing);
    }
    /* If the node is not the reference node, that uses the address from
     * config.conn_info.hostip and config.conn_info.hostport, then the node ip has been
     * allocated by fetchClusterConfiguration, so it must be freed. */
    if (node->ip && strcmp(node->ip, config.conn_info.hostip) != 0) sdsfree(node->ip);
    if (node->redis_config != NULL) freeRedisConfig(node->redis_config);
    zfree(node->slots);
    zfree(node);
}

static void freeClusterNodes(void) {
    int i = 0;
    for (; i < config.cluster_node_count; i++) {
        clusterNode *n = config.cluster_nodes[i];
        if (n) freeClusterNode(n);
    }
    zfree(config.cluster_nodes);
    config.cluster_nodes = NULL;
}

static clusterNode **addClusterNode(clusterNode *node) {
    int count = config.cluster_node_count + 1;
    config.cluster_nodes = zrealloc(config.cluster_nodes,
                                    count * sizeof(*node));
    if (!config.cluster_nodes) return NULL;
    config.cluster_nodes[config.cluster_node_count++] = node;
    return config.cluster_nodes;
}

/* TODO: This should be refactored to use CLUSTER SLOTS, the migrating/importing
 * information is anyway not used.
 */
static int fetchClusterConfiguration(void) {
    int success = 1;
    redisContext *ctx = NULL;
    redisReply *reply =  NULL;
    ctx = getRedisContext(config.conn_info.hostip, config.conn_info.hostport, config.hostsocket);
    if (ctx == NULL) {
        exit(1);
    }
    clusterNode *firstNode = createClusterNode((char *) config.conn_info.hostip,
                                               config.conn_info.hostport);
    if (!firstNode) {success = 0; goto cleanup;}
    reply = redisCommand(ctx, "CLUSTER NODES");
    success = (reply != NULL);
    if (!success) goto cleanup;
    success = (reply->type != REDIS_REPLY_ERROR);
    if (!success) {
        if (config.hostsocket == NULL) {
            fprintf(stderr, "Cluster node %s:%d replied with error:\n%s\n",
                    config.conn_info.hostip, config.conn_info.hostport, reply->str);
        } else {
            fprintf(stderr, "Cluster node %s replied with error:\n%s\n",
                    config.hostsocket, reply->str);
        }
        goto cleanup;
    }
    char *lines = reply->str, *p, *line;
    while ((p = strstr(lines, "\n")) != NULL) {
        *p = '\0';
        line = lines;
        lines = p + 1;
        char *name = NULL, *addr = NULL, *flags = NULL, *master_id = NULL;
        int i = 0;
        while ((p = strchr(line, ' ')) != NULL) {
            *p = '\0';
            char *token = line;
            line = p + 1;
            switch(i++){
            case 0: name = token; break;
            case 1: addr = token; break;
            case 2: flags = token; break;
            case 3: master_id = token; break;
            }
            if (i == 8) break; // Slots
        }
        if (!flags) {
            fprintf(stderr, "Invalid CLUSTER NODES reply: missing flags.\n");
            success = 0;
            goto cleanup;
        }
        int myself = (strstr(flags, "myself") != NULL);
        int is_replica = (strstr(flags, "slave") != NULL ||
                         (master_id != NULL && master_id[0] != '-'));
        if (is_replica) continue;
        if (addr == NULL) {
            fprintf(stderr, "Invalid CLUSTER NODES reply: missing addr.\n");
            success = 0;
            goto cleanup;
        }
        clusterNode *node = NULL;
        char *ip = NULL;
        int port = 0;
        char *paddr = strrchr(addr, ':');
        if (paddr != NULL) {
            *paddr = '\0';
            ip = addr;
            addr = paddr + 1;
            /* If internal bus is specified, then just drop it. */
            if ((paddr = strchr(addr, '@')) != NULL) *paddr = '\0';
            port = atoi(addr);
        }
        if (myself) {
            node = firstNode;
            if (ip != NULL && strcmp(node->ip, ip) != 0) {
                node->ip = sdsnew(ip);
                node->port = port;
            }
        } else {
            node = createClusterNode(sdsnew(ip), port);
        }
        if (node == NULL) {
            success = 0;
            goto cleanup;
        }
        if (name != NULL) node->name = sdsnew(name);
        if (i == 8) {
            int remaining = strlen(line);
            while (remaining > 0) {
                p = strchr(line, ' ');
                if (p == NULL) p = line + remaining;
                remaining -= (p - line);

                char *slotsdef = line;
                *p = '\0';
                if (remaining) {
                    line = p + 1;
                    remaining--;
                } else line = p;
                char *dash = NULL;
                if (slotsdef[0] == '[') {
                    slotsdef++;
                    if ((p = strstr(slotsdef, "->-"))) { // Migrating
                        *p = '\0';
                        p += 3;
                        char *closing_bracket = strchr(p, ']');
                        if (closing_bracket) *closing_bracket = '\0';
                        sds slot = sdsnew(slotsdef);
                        sds dst = sdsnew(p);
                        node->migrating_count += 2;
                        node->migrating =
                            zrealloc(node->migrating,
                                (node->migrating_count * sizeof(sds)));
                        node->migrating[node->migrating_count - 2] =
                            slot;
                        node->migrating[node->migrating_count - 1] =
                            dst;
                    }  else if ((p = strstr(slotsdef, "-<-"))) {//Importing
                        *p = '\0';
                        p += 3;
                        char *closing_bracket = strchr(p, ']');
                        if (closing_bracket) *closing_bracket = '\0';
                        sds slot = sdsnew(slotsdef);
                        sds src = sdsnew(p);
                        node->importing_count += 2;
                        node->importing = zrealloc(node->importing,
                            (node->importing_count * sizeof(sds)));
                        node->importing[node->importing_count - 2] =
                            slot;
                        node->importing[node->importing_count - 1] =
                            src;
                    }
                } else if ((dash = strchr(slotsdef, '-')) != NULL) {
                    p = dash;
                    int start, stop;
                    *p = '\0';
                    start = atoi(slotsdef);
                    stop = atoi(p + 1);
                    while (start <= stop) {
                        int slot = start++;
                        node->slots[node->slots_count++] = slot;
                    }
                } else if (p > slotsdef) {
                    int slot = atoi(slotsdef);
                    node->slots[node->slots_count++] = slot;
                }
            }
        }
        if (node->slots_count == 0) {
            fprintf(stderr,
                    "WARNING: Master node %s:%d has no slots, skipping...\n",
                    node->ip, node->port);
            continue;
        }
        if (!addClusterNode(node)) {
            success = 0;
            goto cleanup;
        }
    }
cleanup:
    if (ctx) redisFree(ctx);
    if (!success) {
        if (config.cluster_nodes) freeClusterNodes();
    }
    if (reply) freeReplyObject(reply);
    return success;
}

/* Request the current cluster slots configuration by calling CLUSTER SLOTS
 * and atomically update the slots after a successful reply. */
static int fetchClusterSlotsConfiguration(client c) {
    UNUSED(c);
    int success = 1, is_fetching_slots = 0, last_update = 0;
    size_t i;
    atomicGet(config.slots_last_update, last_update);
    if (c->slots_last_update < last_update) {
        c->slots_last_update = last_update;
        return -1;
    }
    redisReply *reply = NULL;
    atomicGetIncr(config.is_fetching_slots, is_fetching_slots, 1);
    if (is_fetching_slots) return -1; //TODO: use other codes || errno ?
    atomicSet(config.is_fetching_slots, 1);
    fprintf(stderr,
            "WARNING: Cluster slots configuration changed, fetching new one...\n");
    const char *errmsg = "Failed to update cluster slots configuration";
    static dictType dtype = {
        dictSdsHash,               /* hash function */
        NULL,                      /* key dup */
        NULL,                      /* val dup */
        dictSdsKeyCompare,         /* key compare */
        NULL,                      /* key destructor */
        NULL,                      /* val destructor */
        NULL                       /* allow to expand */
    };
    /* printf("[%d] fetchClusterSlotsConfiguration\n", c->thread_id); */
    dict *masters = dictCreate(&dtype);
    redisContext *ctx = NULL;
    for (i = 0; i < (size_t) config.cluster_node_count; i++) {
        clusterNode *node = config.cluster_nodes[i];
        assert(node->ip != NULL);
        assert(node->name != NULL);
        assert(node->port);
        /* Use first node as entry point to connect to. */
        if (ctx == NULL) {
            ctx = getRedisContext(node->ip, node->port, NULL);
            if (!ctx) {
                success = 0;
                goto cleanup;
            }
        }
        if (node->updated_slots != NULL)
            zfree(node->updated_slots);
        node->updated_slots = NULL;
        node->updated_slots_count = 0;
        dictReplace(masters, node->name, node) ;
    }
    reply = redisCommand(ctx, "CLUSTER SLOTS");
    if (reply == NULL || reply->type == REDIS_REPLY_ERROR) {
        success = 0;
        if (reply)
            fprintf(stderr,"%s\nCLUSTER SLOTS ERROR: %s\n",errmsg,reply->str);
        goto cleanup;
    }
    assert(reply->type == REDIS_REPLY_ARRAY);
    for (i = 0; i < reply->elements; i++) {
        redisReply *r = reply->element[i];
        assert(r->type == REDIS_REPLY_ARRAY);
        assert(r->elements >= 3);
        int from, to, slot;
        from = r->element[0]->integer;
        to = r->element[1]->integer;
        redisReply *nr =  r->element[2];
        assert(nr->type == REDIS_REPLY_ARRAY && nr->elements >= 3);
        assert(nr->element[2]->str != NULL);
        sds name =  sdsnew(nr->element[2]->str);
        dictEntry *entry = dictFind(masters, name);
        if (entry == NULL) {
            success = 0;
            fprintf(stderr, "%s: could not find node with ID %s in current "
                            "configuration.\n", errmsg, name);
            if (name) sdsfree(name);
            goto cleanup;
        }
        sdsfree(name);
        clusterNode *node = dictGetVal(entry);
        if (node->updated_slots == NULL)
            node->updated_slots = zcalloc(CLUSTER_SLOTS * sizeof(int));
        for (slot = from; slot <= to; slot++)
            node->updated_slots[node->updated_slots_count++] = slot;
    }
    updateClusterSlotsConfiguration();
cleanup:
    freeReplyObject(reply);
    redisFree(ctx);
    dictRelease(masters);
    atomicSet(config.is_fetching_slots, 0);
    return success;
}

/* Atomically update the new slots configuration. */
static void updateClusterSlotsConfiguration(void) {
    pthread_mutex_lock(&config.is_updating_slots_mutex);
    atomicSet(config.is_updating_slots, 1);
    int i;
    for (i = 0; i < config.cluster_node_count; i++) {
        clusterNode *node = config.cluster_nodes[i];
        if (node->updated_slots != NULL) {
            int *oldslots = node->slots;
            node->slots = node->updated_slots;
            node->slots_count = node->updated_slots_count;
            node->updated_slots = NULL;
            node->updated_slots_count = 0;
            zfree(oldslots);
        }
    }
    atomicSet(config.is_updating_slots, 0);
    atomicIncr(config.slots_last_update, 1);
    pthread_mutex_unlock(&config.is_updating_slots_mutex);
}

/* Generate random data for redis benchmark. See #7196. */
static void genBenchmarkRandomData(char *data, int count) {
    static uint32_t state = 1234;
    int i = 0;

    while (count--) {
        state = (state*1103515245+12345);
        data[i++] = '0'+((state>>16)&63);
    }
}

/* Returns number of consumed options. */
int parseOptions(int argc, char **argv) {
    int i;
    int lastarg;
    int exit_status = 1;
    char *tls_usage;

    for (i = 1; i < argc; i++) {
        lastarg = (i == (argc-1));

        if (!strcmp(argv[i],"-c")) {
            if (lastarg) goto invalid;
            config.numclients = atoi(argv[++i]);
        } else if (!strcmp(argv[i],"-v") || !strcmp(argv[i], "--version")) {
            sds version = cliVersion();
            printf("redis-benchmark %s\n", version);
            sdsfree(version);
            exit(0);
        } else if (!strcmp(argv[i],"-n")) {
            if (lastarg) goto invalid;
            config.requests = atoi(argv[++i]);
        } else if (!strcmp(argv[i],"-k")) {
            if (lastarg) goto invalid;
            config.keepalive = atoi(argv[++i]);
        } else if (!strcmp(argv[i],"-h")) {
            if (lastarg) goto invalid;
            sdsfree(config.conn_info.hostip);
            config.conn_info.hostip = sdsnew(argv[++i]);
        } else if (!strcmp(argv[i],"-p")) {
            if (lastarg) goto invalid;
            config.conn_info.hostport = atoi(argv[++i]);
            if (config.conn_info.hostport < 0 || config.conn_info.hostport > 65535) {
                fprintf(stderr, "Invalid server port.\n");
                exit(1);
            }
        } else if (!strcmp(argv[i],"-s")) {
            if (lastarg) goto invalid;
            config.hostsocket = strdup(argv[++i]);
        } else if (!strcmp(argv[i],"-x")) {
            config.stdinarg = 1;
        } else if (!strcmp(argv[i],"-a") ) {
            if (lastarg) goto invalid;
            config.conn_info.auth = sdsnew(argv[++i]);
        } else if (!strcmp(argv[i],"--user")) {
            if (lastarg) goto invalid;
            config.conn_info.user = sdsnew(argv[++i]);
        } else if (!strcmp(argv[i],"-u") && !lastarg) {
            parseRedisUri(argv[++i],"redis-benchmark",&config.conn_info,&config.tls);
            if (config.conn_info.hostport < 0 || config.conn_info.hostport > 65535) {
                fprintf(stderr, "Invalid server port.\n");
                exit(1);
            }
            config.input_dbnumstr = sdsfromlonglong(config.conn_info.input_dbnum);
        } else if (!strcmp(argv[i],"-3")) {
            config.resp3 = 1;
        } else if (!strcmp(argv[i],"-d")) {
            if (lastarg) goto invalid;
            config.datasize = atoi(argv[++i]);
            if (config.datasize < 1) config.datasize=1;
            if (config.datasize > 1024*1024*1024) config.datasize = 1024*1024*1024;
            config.datasize_set = 1;
        } else if (!strcmp(argv[i],"-P")) {
            if (lastarg) goto invalid;
            config.pipeline = atoi(argv[++i]);
            if (config.pipeline <= 0) config.pipeline=1;
        } else if (!strcmp(argv[i],"--cxl-ring")) {
            if (lastarg) goto invalid;
            config.cxl_enabled = 1;
            config.cxl_ring_path = strdup(argv[++i]);
        } else if (!strcmp(argv[i],"--cxl-mode")) {
            if (lastarg) goto invalid;
            config.cxl_enabled = 1;
            if (cxlBenchParseMode(argv[++i]) != C_OK) goto invalid;
        } else if (!strcmp(argv[i],"--cxl-ring-map-size")) {
            if (lastarg) goto invalid;
            config.cxl_enabled = 1;
            if (cxlBenchParseSize(argv[++i], &config.cxl_ring_map_size) != C_OK)
                goto invalid;
        } else if (!strcmp(argv[i],"--cxl-ring-offset")) {
            if (lastarg) goto invalid;
            config.cxl_enabled = 1;
            if (cxlBenchParseSize(argv[++i], &config.cxl_ring_offset) != C_OK)
                goto invalid;
        } else if (!strcmp(argv[i],"--cxl-ring-region-base")) {
            if (lastarg) goto invalid;
            config.cxl_enabled = 1;
            if (cxlBenchParseSize(argv[++i], &config.cxl_ring_region_base) != C_OK)
                goto invalid;
        } else if (!strcmp(argv[i],"--cxl-ring-region-size")) {
            if (lastarg) goto invalid;
            config.cxl_enabled = 1;
            if (cxlBenchParseSize(argv[++i], &config.cxl_ring_region_size) != C_OK)
                goto invalid;
        } else if (!strcmp(argv[i],"--cxl-ring-count")) {
            if (lastarg) goto invalid;
            config.cxl_enabled = 1;
            config.cxl_ring_count = atoi(argv[++i]);
            if (config.cxl_ring_count <= 0 || config.cxl_ring_count > MAX_THREADS)
                goto invalid;
        } else if (!strcmp(argv[i],"--cxl-paper-redis")) {
            config.cxl_enabled = 1;
            config.cxl_paper_preset = 1;
            config.requests = 2000000;
            config.pipeline = 256;
            if (config.tests == NULL)
                config.tests = sdsnew(",set,get,");
        } else if (!strcmp(argv[i],"--ycsb")) {
            config.ycsb_enabled = 1;
        } else if (!strcmp(argv[i],"--ycsb-transport")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            char *transport = argv[++i];
            if (!strcasecmp(transport, "tcp")) {
                config.ycsb_transport = YCSB_TRANSPORT_TCP;
            } else if (!strcasecmp(transport, "cxl")) {
                config.ycsb_transport = YCSB_TRANSPORT_CXL;
                config.cxl_enabled = 1;
            } else {
                goto invalid;
            }
        } else if (!strcmp(argv[i],"--ycsb-workload")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            if (cxlYcsbParseWorkload(argv[++i]) != C_OK) goto invalid;
        } else if (!strcmp(argv[i],"--ycsb-phase")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            if (cxlYcsbParsePhase(argv[++i]) != C_OK) goto invalid;
        } else if (!strcmp(argv[i],"--ycsb-record-count")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            if (cxlYcsbParseUInt64(argv[++i],
                                   &config.ycsb_record_count) != C_OK)
                goto invalid;
        } else if (!strcmp(argv[i],"--ycsb-operation-count")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            if (cxlYcsbParseUInt64(argv[++i],
                                   &config.ycsb_operation_count) != C_OK)
                goto invalid;
        } else if (!strcmp(argv[i],"--ycsb-insert-start")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            if (cxlYcsbParseUInt64(argv[++i],
                                   &config.ycsb_insert_start) != C_OK)
                goto invalid;
            config.ycsb_insert_start_set = 1;
        } else if (!strcmp(argv[i],"--ycsb-request-distribution")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            int dist = cxlYcsbParseDistribution(argv[++i], 1);
            if (dist == C_ERR) goto invalid;
            config.ycsb_request_distribution = dist;
        } else if (!strcmp(argv[i],"--ycsb-scan-length-distribution")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            int dist = cxlYcsbParseDistribution(argv[++i], 0);
            if (dist == C_ERR) goto invalid;
            config.ycsb_scan_length_distribution = dist;
        } else if (!strcmp(argv[i],"--ycsb-max-scan-length")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            config.ycsb_max_scan_length = atoi(argv[++i]);
            if (config.ycsb_max_scan_length <= 0 ||
                config.ycsb_max_scan_length > UINT16_MAX)
                goto invalid;
        } else if (!strcmp(argv[i],"--ycsb-field-count")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            config.ycsb_field_count = atoi(argv[++i]);
            if (config.ycsb_field_count <= 0) goto invalid;
        } else if (!strcmp(argv[i],"--ycsb-field-length")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            config.ycsb_field_length = atoi(argv[++i]);
            if (config.ycsb_field_length <= 0) goto invalid;
        } else if (!strcmp(argv[i],"--ycsb-read-all-fields")) {
            config.ycsb_enabled = 1;
            config.ycsb_read_all_fields = 1;
        } else if (!strcmp(argv[i],"--ycsb-seed")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            if (cxlYcsbParseUInt64(argv[++i], &config.ycsb_seed) != C_OK)
                goto invalid;
        } else if (!strcmp(argv[i],"--ycsb-key-prefix")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            config.ycsb_key_prefix = strdup(argv[++i]);
        } else if (!strcmp(argv[i],"--ycsb-key-width")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            config.ycsb_key_width = atoi(argv[++i]);
            if (config.ycsb_key_width <= 0 || config.ycsb_key_width > 40)
                goto invalid;
        } else if (!strcmp(argv[i],"--ycsb-zipf-theta")) {
            if (lastarg) goto invalid;
            config.ycsb_enabled = 1;
            config.ycsb_zipf_theta = strtod(argv[++i], NULL);
            if (config.ycsb_zipf_theta <= 0.0 ||
                config.ycsb_zipf_theta >= 1.0)
                goto invalid;
        } else if (!strcmp(argv[i],"--server-ready-timeout-ms")) {
            if (lastarg) goto invalid;
            config.server_ready_timeout_ms = atoi(argv[++i]);
            if (config.server_ready_timeout_ms < 0) goto invalid;
        } else if (!strcmp(argv[i],"--gem5-client-id")) {
            if (lastarg) goto invalid;
            config.gem5_client_id = atoi(argv[++i]);
            if (config.gem5_client_id < 0) goto invalid;
        } else if (!strcmp(argv[i],"--gem5-client-count")) {
            if (lastarg) goto invalid;
            config.gem5_client_count = atoi(argv[++i]);
            if (config.gem5_client_count < 0) goto invalid;
        } else if (!strcmp(argv[i],"--gem5-client-sync-dir")) {
            if (lastarg) goto invalid;
            config.gem5_client_sync_dir = strdup(argv[++i]);
        } else if (!strcmp(argv[i],"--gem5-client-sync-timeout-ms")) {
            if (lastarg) goto invalid;
            config.gem5_client_sync_timeout_ms = atoi(argv[++i]);
            if (config.gem5_client_sync_timeout_ms < 0) goto invalid;
        } else if (!strcmp(argv[i],"--shutdown-server-after")) {
            config.shutdown_server_after = 1;
        } else if (!strcmp(argv[i],"-r")) {
            if (lastarg) goto invalid;
            const char *next = argv[++i], *p = next;
            if (*p == '-') {
                p++;
                if (*p < '0' || *p > '9') goto invalid;
            }
            config.randomkeys = 1;
            config.randomkeys_keyspacelen = atoi(next);
            if (config.randomkeys_keyspacelen < 0)
                config.randomkeys_keyspacelen = 0;
        } else if (!strcmp(argv[i],"-q")) {
            config.quiet = 1;
        } else if (!strcmp(argv[i],"--csv")) {
            config.csv = 1;
        } else if (!strcmp(argv[i],"-l")) {
            config.loop = 1;
        } else if (!strcmp(argv[i],"-I")) {
            config.idlemode = 1;
        } else if (!strcmp(argv[i],"-e")) {
            fprintf(stderr,
                    "WARNING: -e option has no effect. "
                    "We now immediately exit on error to avoid false results.\n");
        } else if (!strcmp(argv[i],"--seed")) {
            if (lastarg) goto invalid;
            int rand_seed = atoi(argv[++i]);
            srandom(rand_seed);
            init_genrand64(rand_seed);
        } else if (!strcmp(argv[i],"-t")) {
            if (lastarg) goto invalid;
            /* We get the list of tests to run as a string in the form
             * get,set,lrange,...,test_N. Then we add a comma before and
             * after the string in order to make sure that searching
             * for ",testname," will always get a match if the test is
             * enabled. */
            config.tests = sdsnew(",");
            config.tests = sdscat(config.tests,(char*)argv[++i]);
            config.tests = sdscat(config.tests,",");
            sdstolower(config.tests);
        } else if (!strcmp(argv[i],"--dbnum")) {
            if (lastarg) goto invalid;
            config.conn_info.input_dbnum = atoi(argv[++i]);
            config.input_dbnumstr = sdsfromlonglong(config.conn_info.input_dbnum);
        } else if (!strcmp(argv[i],"--precision")) {
            if (lastarg) goto invalid;
            config.precision = atoi(argv[++i]);
            if (config.precision < 0) config.precision = DEFAULT_LATENCY_PRECISION;
            if (config.precision > MAX_LATENCY_PRECISION) config.precision = MAX_LATENCY_PRECISION;
        } else if (!strcmp(argv[i],"--threads")) {
             if (lastarg) goto invalid;
             config.num_threads = atoi(argv[++i]);
             if (config.num_threads > MAX_THREADS) {
                 fprintf(stderr,
                         "WARNING: Too many threads, limiting threads to %d.\n",
                         MAX_THREADS);
                config.num_threads = MAX_THREADS;
             } else if (config.num_threads < 0) config.num_threads = 0;
        } else if (!strcmp(argv[i],"--threads-use-main")) {
            config.threads_use_main = 1;
        } else if (!strcmp(argv[i],"--cluster")) {
            config.cluster_mode = 1;
        } else if (!strcmp(argv[i],"--enable-tracking")) {
            config.enable_tracking = 1;
        } else if (!strcmp(argv[i],"--help")) {
            exit_status = 0;
            goto usage;
        #ifdef USE_OPENSSL
        } else if (!strcmp(argv[i],"--tls")) {
            config.tls = 1;
        } else if (!strcmp(argv[i],"--sni")) {
            if (lastarg) goto invalid;
            config.sslconfig.sni = strdup(argv[++i]);
        } else if (!strcmp(argv[i],"--cacertdir")) {
            if (lastarg) goto invalid;
            config.sslconfig.cacertdir = strdup(argv[++i]);
        } else if (!strcmp(argv[i],"--cacert")) {
            if (lastarg) goto invalid;
            config.sslconfig.cacert = strdup(argv[++i]);
        } else if (!strcmp(argv[i],"--insecure")) {
            config.sslconfig.skip_cert_verify = 1;
        } else if (!strcmp(argv[i],"--cert")) {
            if (lastarg) goto invalid;
            config.sslconfig.cert = strdup(argv[++i]);
        } else if (!strcmp(argv[i],"--key")) {
            if (lastarg) goto invalid;
            config.sslconfig.key = strdup(argv[++i]);
        } else if (!strcmp(argv[i],"--tls-ciphers")) {
            if (lastarg) goto invalid;
            config.sslconfig.ciphers = strdup(argv[++i]);
        #ifdef TLS1_3_VERSION
        } else if (!strcmp(argv[i],"--tls-ciphersuites")) {
            if (lastarg) goto invalid;
            config.sslconfig.ciphersuites = strdup(argv[++i]);
        #endif
        #endif
        } else {
            /* Assume the user meant to provide an option when the arg starts
             * with a dash. We're done otherwise and should use the remainder
             * as the command and arguments for running the benchmark. */
            if (argv[i][0] == '-') goto invalid;
            return i;
        }
    }

    return i;

invalid:
    printf("Invalid option \"%s\" or option argument missing\n\n",argv[i]);

usage:
    tls_usage =
#ifdef USE_OPENSSL
" --tls              Establish a secure TLS connection.\n"
" --sni <host>       Server name indication for TLS.\n"
" --cacert <file>    CA Certificate file to verify with.\n"
" --cacertdir <dir>  Directory where trusted CA certificates are stored.\n"
"                    If neither cacert nor cacertdir are specified, the default\n"
"                    system-wide trusted root certs configuration will apply.\n"
" --insecure         Allow insecure TLS connection by skipping cert validation.\n"
" --cert <file>      Client certificate to authenticate with.\n"
" --key <file>       Private key file to authenticate with.\n"
" --tls-ciphers <list> Sets the list of preferred ciphers (TLSv1.2 and below)\n"
"                    in order of preference from highest to lowest separated by colon (\":\").\n"
"                    See the ciphers(1ssl) manpage for more information about the syntax of this string.\n"
#ifdef TLS1_3_VERSION
" --tls-ciphersuites <list> Sets the list of preferred ciphersuites (TLSv1.3)\n"
"                    in order of preference from highest to lowest separated by colon (\":\").\n"
"                    See the ciphers(1ssl) manpage for more information about the syntax of this string,\n"
"                    and specifically for TLSv1.3 ciphersuites.\n"
#endif
#endif
"";

    printf(
"%s%s%s%s", /* Split to avoid strings longer than 4095 (-Woverlength-strings). */
"Usage: redis-benchmark [OPTIONS] [COMMAND ARGS...]\n\n"
"Options:\n"
" -h <hostname>      Server hostname (default 127.0.0.1)\n"
" -p <port>          Server port (default 6379)\n"
" -s <socket>        Server socket (overrides host and port)\n"
" -a <password>      Password for Redis Auth\n"
" --user <username>  Used to send ACL style 'AUTH username pass'. Needs -a.\n"
" -u <uri>           Server URI on format redis://user:password@host:port/dbnum\n"
"                    User, password and dbnum are optional. For authentication\n"
"                    without a username, use username 'default'. For TLS, use\n"
"                    the scheme 'rediss'.\n"
" -c <clients>       Number of parallel connections (default 50).\n"
"                    Note: If --cluster is used then number of clients has to be\n"
"                    the same or higher than the number of nodes.\n"
" -n <requests>      Total number of requests (default 100000)\n"
" -d <size>          Data size of SET/GET value in bytes (default 3)\n"
" --dbnum <db>       SELECT the specified db number (default 0)\n"
" -3                 Start session in RESP3 protocol mode.\n"
" --threads <num>    Enable multi-thread mode.\n"
" --threads-use-main Count the main thread as one benchmark worker.\n"
" --cluster          Enable cluster mode.\n"
"                    If the command is supplied on the command line in cluster\n"
"                    mode, the key must contain \"{tag}\". Otherwise, the\n"
"                    command will not be sent to the right cluster node.\n"
" --enable-tracking  Send CLIENT TRACKING on before starting benchmark.\n"
" -k <boolean>       1=keep alive 0=reconnect (default 1)\n"
" -r <keyspacelen>   Use random keys for SET/GET/INCR, random values for SADD,\n"
"                    random members and scores for ZADD.\n"
"                    Using this option the benchmark will expand the string\n"
"                    __rand_int__ inside an argument with a 12 digits number in\n"
"                    the specified range from 0 to keyspacelen-1. The\n"
"                    substitution changes every time a command is executed.\n"
"                    Default tests use this to hit random keys in the specified\n"
"                    range.\n"
"                    Note: If -r is omitted, all commands in a benchmark will\n"
"                    use the same key.\n"
" -P <numreq>        Pipeline <numreq> requests. Default 1 (no pipeline).\n"
" --cxl-ring <path>  Use CXL shared-memory ring instead of TCP for GET/SET.\n"
" --cxl-mode <mode>  native-shm or dsm-tee. Default native-shm.\n"
" --cxl-ring-count <n> Number of shared-memory rings; use >= --threads.\n"
" --cxl-ring-map-size <bytes> Shared mapping size, supports K/M/G suffixes.\n"
" --cxl-paper-redis  Preset paper redis-benchmark config: -n 2000000 -P 256 -t set,get.\n",
" --ycsb             Enable built-in YCSB mode.\n"
" --ycsb-transport <tcp|cxl> YCSB transport. Default tcp unless --cxl-ring is set.\n"
" --ycsb-workload <a|b|c|d|e|f> YCSB Core Workload to run.\n"
" --ycsb-phase <load|run|load-run> Load records, run operations, or both.\n"
" --ycsb-record-count <n> Number of records in the initial database.\n"
" --ycsb-operation-count <n> Number of YCSB run-phase operations.\n"
" --ycsb-request-distribution <uniform|zipfian|latest> Key distribution.\n"
" --ycsb-scan-length-distribution <uniform|zipfian> Scan length distribution.\n"
" --ycsb-max-scan-length <n> Maximum Workload E scan length, default 100.\n"
" --ycsb-field-count <n> Number of fields per record, default 10.\n"
" --ycsb-field-length <n> Bytes per field, default 100.\n"
" --ycsb-key-prefix <str> Key prefix, default user.\n"
" --server-ready-timeout-ms <ms> Retry initial TCP connection until timeout.\n"
" --shutdown-server-after Send SHUTDOWN NOSAVE after benchmark completion.\n"
" --gem5-client-id <n> Client id used with --shutdown-server-after coordination.\n"
" --gem5-client-count <n> Number of client processes in the coordinated run.\n"
" --gem5-client-sync-dir <path> Directory for coordinated client completion files.\n"
" -q                 Quiet. Just show query/sec values\n"
" --precision        Number of decimal places to display in latency output (default 0)\n"
" --csv              Output in CSV format\n"
" -l                 Loop. Run the tests forever\n"
" -t <tests>         Only run the comma separated list of tests. The test\n"
"                    names are the same as the ones produced as output.\n"
"                    The -t option is ignored if a specific command is supplied\n"
"                    on the command line.\n"
" -I                 Idle mode. Just open N idle connections and wait.\n"
" -x                 Read last argument from STDIN.\n"
" --seed <num>       Set the seed for random number generator. Default seed is based on time.\n",
tls_usage,
" --help             Output this help and exit.\n"
" --version          Output version and exit.\n\n"
"Examples:\n\n"
" Run the benchmark with the default configuration against 127.0.0.1:6379:\n"
"   $ redis-benchmark\n\n"
" Use 20 parallel clients, for a total of 100k requests, against 192.168.1.1:\n"
"   $ redis-benchmark -h 192.168.1.1 -p 6379 -n 100000 -c 20\n\n"
" Fill 127.0.0.1:6379 with about 1 million keys only using the SET test:\n"
"   $ redis-benchmark -t set -n 1000000 -r 100000000\n\n"
" Benchmark 127.0.0.1:6379 for a few commands producing CSV output:\n"
"   $ redis-benchmark -t ping,set,get -n 100000 --csv\n\n"
" Benchmark a specific command line:\n"
"   $ redis-benchmark -r 10000 -n 10000 eval 'return redis.call(\"ping\")' 0\n\n"
" Fill a list with 10000 random elements:\n"
"   $ redis-benchmark -r 10000 -n 10000 lpush mylist __rand_int__\n\n"
" On user specified command lines __rand_int__ is replaced with a random integer\n"
" with a range of values selected by the -r option.\n"
    );
    exit(exit_status);
}

int showThroughput(struct aeEventLoop *eventLoop, long long id, void *clientData) {
    UNUSED(eventLoop);
    UNUSED(id);
    benchmarkThread *thread = (benchmarkThread *)clientData;
    int liveclients = 0;
    int requests_finished = 0;
    int previous_requests_finished = 0;
    long long current_tick = mstime();
    atomicGet(config.liveclients, liveclients);
    atomicGet(config.requests_finished, requests_finished);
    atomicGet(config.previous_requests_finished, previous_requests_finished);

    if (liveclients == 0 && requests_finished != config.requests) {
        fprintf(stderr,"All clients disconnected... aborting.\n");
        exit(1);
    }
    if (config.num_threads && requests_finished >= config.requests) {
        aeStop(eventLoop);
        return AE_NOMORE;
    }
    if (config.csv) return SHOW_THROUGHPUT_INTERVAL;
    /* only first thread output throughput */
    if (thread != NULL && thread->index != 0) {
        return SHOW_THROUGHPUT_INTERVAL;
    }
    if (config.idlemode == 1) {
        printf("clients: %d\r", config.liveclients);
        fflush(stdout);
        return SHOW_THROUGHPUT_INTERVAL;
    }
    const float dt = (float)(current_tick-config.start)/1000.0;
    const float rps = (float)requests_finished/dt;
    const float instantaneous_dt = (float)(current_tick-config.previous_tick)/1000.0;
    const float instantaneous_rps = (float)(requests_finished-previous_requests_finished)/instantaneous_dt;
    config.previous_tick = current_tick;
    atomicSet(config.previous_requests_finished,requests_finished);
    printf("%*s\r", config.last_printed_bytes, " "); /* ensure there is a clean line */
    int printed_bytes = printf("%s: rps=%.1f (overall: %.1f) avg_msec=%.3f (overall: %.3f)\r", config.title, instantaneous_rps, rps, hdr_mean(config.current_sec_latency_histogram)/1000.0f, hdr_mean(config.latency_histogram)/1000.0f);
    config.last_printed_bytes = printed_bytes;
    hdr_reset(config.current_sec_latency_histogram);
    fflush(stdout);
    return SHOW_THROUGHPUT_INTERVAL;
}

/* Return true if the named test was selected using the -t command line
 * switch, or if all the tests are selected (no -t passed by user). */
int test_is_selected(const char *name) {
    char buf[256];
    int l = strlen(name);

    if (config.tests == NULL) return 1;
    buf[0] = ',';
    memcpy(buf+1,name,l);
    buf[l+1] = ',';
    buf[l+2] = '\0';
    return strstr(config.tests,buf) != NULL;
}

typedef struct cxlBenchCtx {
    int fd;
    uint8_t *mm;
    size_t map_size;
    size_t map_offset;
    int ring_count;
    size_t region_base;
    size_t region_size;
    struct cxl_ring_region *rings;
    volatile int errors;
    volatile int issued;
    volatile int finished;
    long long start_us;
    long long end_us;
    long long total_latency_us;
    long long *latencies_us;
    char *value;
    int value_len;
    int op;
    int ycsb_target_ops;
    int ycsb_load_phase;
    volatile unsigned long long ycsb_next_insert_id;
    volatile long long ycsb_cxl_gets;
    volatile long long ycsb_cxl_sets;
    volatile long long ycsb_cxl_scans;
} cxlBenchCtx;

typedef struct cxlBenchThreadArg {
    cxlBenchCtx *ctx;
    int index;
} cxlBenchThreadArg;

typedef struct cxlYcsbZipf {
    unsigned long long items;
    double theta;
    double zeta2theta;
    double alpha;
    double zetan;
    double eta;
} cxlYcsbZipf;

typedef struct cxlYcsbOpStats {
    volatile int count;
    volatile long long total_latency_us;
    long long *latencies_us;
} cxlYcsbOpStats;

typedef struct cxlYcsbPending {
    int logical_op;
    unsigned long long key_id;
    uint16_t scan_len;
    long long start_us;
} cxlYcsbPending;

static cxlYcsbOpStats ycsb_stats[CXL_YCSB_OP_MAX];
static cxlYcsbZipf ycsb_key_zipf;
static cxlYcsbZipf ycsb_scan_zipf;

static int cxlBenchParseSize(const char *arg, size_t *out) {
    if (!arg || !out || !arg[0]) return C_ERR;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(arg, &end, 0);
    if (errno != 0 || end == arg) return C_ERR;

    unsigned long long multiplier = 1ULL;
    if (end && *end != '\0') {
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

static int cxlYcsbParseUInt64(const char *arg, unsigned long long *out) {
    if (!arg || !arg[0] || !out) return C_ERR;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0') return C_ERR;
    *out = value;
    return C_OK;
}

static int cxlYcsbParseWorkload(const char *workload) {
    if (!workload || !workload[0]) return C_ERR;
    if (!strcasecmp(workload, "a") || !strcasecmp(workload, "workloada")) {
        config.ycsb_workload = CXL_YCSB_WORKLOAD_A;
        return C_OK;
    }
    if (!strcasecmp(workload, "b") || !strcasecmp(workload, "workloadb")) {
        config.ycsb_workload = CXL_YCSB_WORKLOAD_B;
        return C_OK;
    }
    if (!strcasecmp(workload, "c") || !strcasecmp(workload, "workloadc")) {
        config.ycsb_workload = CXL_YCSB_WORKLOAD_C;
        return C_OK;
    }
    if (!strcasecmp(workload, "d") || !strcasecmp(workload, "workloadd")) {
        config.ycsb_workload = CXL_YCSB_WORKLOAD_D;
        return C_OK;
    }
    if (!strcasecmp(workload, "e") || !strcasecmp(workload, "workloade")) {
        config.ycsb_workload = CXL_YCSB_WORKLOAD_E;
        return C_OK;
    }
    if (!strcasecmp(workload, "f") || !strcasecmp(workload, "workloadf")) {
        config.ycsb_workload = CXL_YCSB_WORKLOAD_F;
        return C_OK;
    }
    return C_ERR;
}

static int cxlYcsbParsePhase(const char *phase) {
    if (!phase || !phase[0]) return C_ERR;
    if (!strcasecmp(phase, "load")) {
        config.ycsb_phase = CXL_YCSB_PHASE_LOAD;
        return C_OK;
    }
    if (!strcasecmp(phase, "run")) {
        config.ycsb_phase = CXL_YCSB_PHASE_RUN;
        return C_OK;
    }
    if (!strcasecmp(phase, "load-run") || !strcasecmp(phase, "loadrun")) {
        config.ycsb_phase = CXL_YCSB_PHASE_LOAD_RUN;
        return C_OK;
    }
    return C_ERR;
}

static int cxlYcsbParseDistribution(const char *dist, int allow_latest) {
    if (!dist || !dist[0]) return C_ERR;
    if (!strcasecmp(dist, "uniform")) return CXL_YCSB_DIST_UNIFORM;
    if (!strcasecmp(dist, "zipfian")) return CXL_YCSB_DIST_ZIPFIAN;
    if (allow_latest && !strcasecmp(dist, "latest"))
        return CXL_YCSB_DIST_LATEST;
    return C_ERR;
}

static const char *cxlBenchModeName(void) {
    switch (config.cxl_mode) {
    case CXL_BENCH_MODE_DSM_TEE:
        return "DSM-TEE";
    default:
        return "NativeShm";
    }
}

static const char *cxlBenchDefaultPath(void) {
    if (config.cxl_ring_path) return config.cxl_ring_path;
    if (config.cxl_mode == CXL_BENCH_MODE_DSM_TEE) return "/dev/gem5_dsm_tee";
    return "/dev/gem5_cxl_mem";
}

static int cxlBenchParseMode(const char *mode) {
    if (!strcasecmp(mode, "native-shm") || !strcasecmp(mode, "nativeshm")) {
        config.cxl_mode = CXL_BENCH_MODE_NATIVE_SHM;
        return C_OK;
    }
    if (!strcasecmp(mode, "dsm-tee") || !strcasecmp(mode, "dsmtee")) {
        config.cxl_mode = CXL_BENCH_MODE_DSM_TEE;
        return C_OK;
    }
    return C_ERR;
}

static int cxlBenchWaitAttachRegion(void *base, size_t size,
                                    struct cxl_ring_region *region) {
    long long deadline = ustime() + CXL_BENCH_ATTACH_TIMEOUT_US;

    for (int tries = 0; tries < CXL_BENCH_ATTACH_MAX_TRIES; tries++) {
        if (cxlRingRegionAttach(base, size, region) == 0 &&
            cxlRingRegionIsReady(region)) {
            CXL_BENCH_DEBUGF("CXL benchmark: attached ready ring base=%p size=%zu tries=%d\n",
                             base, size, tries);
            return C_OK;
        }

        if (tries > 1024 && ustime() >= deadline)
            break;
        sched_yield();
    }
    CXL_BENCH_DEBUGF("CXL benchmark: attach timeout base=%p size=%zu\n",
                     base, size);
    return C_ERR;
}

static int cxlBenchOpenAndMap(cxlBenchCtx *ctx) {
    const char *path = cxlBenchDefaultPath();
    CXL_BENCH_DEBUGF("CXL benchmark: open path=%s map_size=%zu offset=%zu base=%zu region_size=%zu rings=%d\n",
                     path, ctx->map_size, ctx->map_offset, ctx->region_base,
                     ctx->region_size, ctx->ring_count);
    ctx->fd = open(path, O_RDWR);
    if (ctx->fd < 0 && errno == ENOENT && strncmp(path, "/dev/", 5) != 0)
        ctx->fd = open(path, O_RDWR | O_CREAT, 0600);
    if (ctx->fd < 0) {
        fprintf(stderr, "CXL benchmark: open(%s) failed: %s\n", path, strerror(errno));
        return C_ERR;
    }

    struct stat st;
    int have_stat = fstat(ctx->fd, &st) == 0;
    if (!have_stat && strncmp(path, "/dev/", 5) != 0) {
        fprintf(stderr, "CXL benchmark: fstat failed: %s\n", strerror(errno));
        close(ctx->fd);
        ctx->fd = -1;
        return C_ERR;
    }
    if (have_stat && S_ISREG(st.st_mode)) {
        off_t needed = (off_t)(ctx->map_offset + ctx->map_size);
        if (st.st_size < needed && ftruncate(ctx->fd, needed) != 0) {
            fprintf(stderr, "CXL benchmark: ftruncate failed: %s\n", strerror(errno));
            close(ctx->fd);
            ctx->fd = -1;
            return C_ERR;
        }
    }

    ctx->mm = mmap(NULL, ctx->map_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED, ctx->fd, (off_t)ctx->map_offset);
    if (ctx->mm == MAP_FAILED) {
        fprintf(stderr, "CXL benchmark: mmap failed: %s\n", strerror(errno));
        close(ctx->fd);
        ctx->fd = -1;
        ctx->mm = NULL;
        return C_ERR;
    }
    CXL_BENCH_DEBUGF("CXL benchmark: mapped mm=%p\n", ctx->mm);

    ctx->rings = zmalloc(sizeof(*ctx->rings) * ctx->ring_count);
    for (int i = 0; i < ctx->ring_count; i++) {
        size_t off = ctx->region_base + (size_t)i * ctx->region_size;
        if (off > ctx->map_size || ctx->region_size > ctx->map_size - off) {
            fprintf(stderr, "CXL benchmark: ring %d is out of mapped range\n", i);
            return C_ERR;
        }
        void *base = ctx->mm + off;
        if (cxlBenchWaitAttachRegion(base, ctx->region_size,
                                     &ctx->rings[i]) != C_OK) {
            fprintf(stderr,
                    "CXL benchmark: ring %d attach timed out waiting for server readiness\n",
                    i);
            return C_ERR;
        }
        CXL_BENCH_DEBUGF("CXL benchmark: ring %d attached off=%zu flags=%#x\n",
                         i, off,
                         __atomic_load_n(&ctx->rings[i].hdr->flags,
                                         __ATOMIC_ACQUIRE));
    }
    return C_OK;
}

static void cxlBenchClose(cxlBenchCtx *ctx) {
    if (ctx->mm && ctx->mm != MAP_FAILED) munmap(ctx->mm, ctx->map_size);
    if (ctx->fd >= 0) close(ctx->fd);
    if (ctx->rings) zfree(ctx->rings);
    if (ctx->latencies_us) zfree(ctx->latencies_us);
    if (ctx->value) zfree(ctx->value);
}

static int cxlBenchBuildRawRequest(int op, const char *key, int key_len,
                                   const char *value, uint16_t value_len,
                                   uint8_t *buf, uint32_t *len_out) {
    if (!key || key_len <= 0 || key_len > 255 || !buf || !len_out)
        return C_ERR;
    if (op == CXL_OP_SET && value_len != 0U && value == NULL)
        return C_ERR;
    if (op != CXL_OP_SET && value != NULL)
        return C_ERR;

    uint32_t payload_value_len = op == CXL_OP_SET ? value_len : 0U;
    uint32_t need = 4U + (uint32_t)key_len + payload_value_len;
    if (need > CXL_RING_MAX_PAYLOAD) return C_ERR;

    buf[0] = (uint8_t)op;
    buf[1] = (uint8_t)key_len;
    buf[2] = (uint8_t)(value_len & 0xffU);
    buf[3] = (uint8_t)((value_len >> 8) & 0xffU);
    memcpy(buf + 4U, key, key_len);
    if (payload_value_len != 0U)
        memcpy(buf + 4U + key_len, value, payload_value_len);
    *len_out = need;
    return C_OK;
}

static int cxlBenchBuildRequest(cxlBenchCtx *ctx, int request_id,
                                uint8_t *buf, uint32_t *len_out) {
    char keybuf[256];
    int key_id = 0;
    if (config.randomkeys && config.randomkeys_keyspacelen > 0)
        key_id = request_id % config.randomkeys_keyspacelen;
    int key_len = snprintf(keybuf, sizeof(keybuf), "key:%012d", key_id);
    if (key_len <= 0 || key_len > 255) return C_ERR;

    uint16_t value_len = ctx->op == CXL_OP_SET ? (uint16_t)ctx->value_len : 0U;
    return cxlBenchBuildRawRequest(ctx->op, keybuf, key_len,
                                   ctx->op == CXL_OP_SET ? ctx->value : NULL,
                                   value_len, buf, len_out);
}

static int cxlBenchSendRequest(cxlBenchCtx *ctx, int ring_idx, uint32_t cid,
                               uint8_t *plain, uint32_t plain_len) {
    struct cxl_ring_queue_view *q = &ctx->rings[ring_idx].q21;
    int spins = 0;
    while (!ctx->errors) {
        int rc = cxlRingQueueSend(q, cid, CXL_RING_MSG_DATA, 0U,
                                  plain, plain_len);
        if (rc == 1) {
            CXL_BENCH_DEBUGF("CXL benchmark: sent ring=%d cid=%u len=%u spins=%d\n",
                             ring_idx, cid, plain_len, spins);
            return C_OK;
        }
        if (rc < 0) return C_ERR;
        spins++;
        sched_yield();
    }
    return C_ERR;
}

static int cxlBenchRecvResponse(cxlBenchCtx *ctx, int ring_idx, uint32_t cid,
                                int *status_out, uint16_t *value_len_out) {
    uint32_t rcid = 0, len = 0;
    uint16_t type = 0, flags = 0;
    uint8_t *payload = NULL;
    int spins = 0;
    while (!ctx->errors) {
        int rc = cxlRingQueueRecv(&ctx->rings[ring_idx].q12, &rcid, &type,
                                  &flags, &payload, &len);
        if (rc == 0) {
            spins++;
            sched_yield();
            continue;
        }
        if (rc < 0 || type != CXL_RING_MSG_DATA || rcid != cid)
            return C_ERR;
        UNUSED(flags);

        if (len < 4U) return C_ERR;
        *status_out = payload[0];
        *value_len_out = (uint16_t)payload[1] | ((uint16_t)payload[2] << 8);
        if ((uint32_t)*value_len_out + 4U > len) return C_ERR;
        CXL_BENCH_DEBUGF("CXL benchmark: recv ring=%d cid=%u status=%d len=%u spins=%d\n",
                         ring_idx, cid, *status_out, len, spins);
        return C_OK;
    }
    return C_ERR;
}

static void *cxlBenchThreadMain(void *argptr) {
    cxlBenchThreadArg *arg = argptr;
    cxlBenchCtx *ctx = arg->ctx;
    int ring_idx = arg->index % ctx->ring_count;
    uint32_t cid = (uint32_t)arg->index + 1U;
    uint8_t req[CXL_RING_MAX_PAYLOAD];
    long long *starts = zmalloc(sizeof(long long) * config.pipeline);
    CXL_BENCH_DEBUGF("CXL benchmark: worker start index=%d ring=%d cid=%u\n",
                     arg->index, ring_idx, cid);

    while (!ctx->errors) {
        int batch = 0;
        for (; batch < config.pipeline; batch++) {
            int request_id = __sync_fetch_and_add(&ctx->issued, 1);
            if (request_id >= config.requests) break;
            uint32_t req_len = 0;
            if (cxlBenchBuildRequest(ctx, request_id, req, &req_len) != C_OK ||
                cxlBenchSendRequest(ctx, ring_idx, cid, req, req_len) != C_OK) {
                ctx->errors = 1;
                break;
            }
            starts[batch] = ustime();
        }
        if (batch == 0 || ctx->errors) break;

        for (int i = 0; i < batch; i++) {
            int status = 0;
            uint16_t value_len = 0;
            if (cxlBenchRecvResponse(ctx, ring_idx, cid, &status, &value_len) != C_OK) {
                ctx->errors = 1;
                break;
            }
            if (status == CXL_STATUS_ERR) {
                ctx->errors = 1;
                break;
            }
            long long latency = ustime() - starts[i];
            int idx = __sync_fetch_and_add(&ctx->finished, 1);
            if (idx < config.requests) ctx->latencies_us[idx] = latency;
            __sync_fetch_and_add(&ctx->total_latency_us, latency);
            UNUSED(value_len);
        }
    }
    zfree(starts);
    return NULL;
}

static int cmpLongLong(const void *a, const void *b) {
    long long aa = *(const long long *)a;
    long long bb = *(const long long *)b;
    return (aa > bb) - (aa < bb);
}

static long long cxlBenchPercentile(long long *values, int count, int pct) {
    if (count <= 0) return 0;
    long long idx = ((long long)count * pct) / 100;
    if (idx >= count) idx = count - 1;
    return values[idx];
}

static void cxlBenchReport(const char *title, cxlBenchCtx *ctx) {
    int count = ctx->finished;
    if (count <= 0) {
        fprintf(stderr, "%s: no completed requests\n", title);
        return;
    }

    qsort(ctx->latencies_us, count, sizeof(long long), cmpLongLong);
    double seconds = (double)(ctx->end_us - ctx->start_us) / 1000000.0;
    if (seconds <= 0.0) seconds = 0.000001;
    double rps = (double)count / seconds;
    double avg_ms = ((double)ctx->total_latency_us / (double)count) / 1000.0;
    double min_ms = (double)ctx->latencies_us[0] / 1000.0;
    double p50_ms = (double)cxlBenchPercentile(ctx->latencies_us, count, 50) / 1000.0;
    double p95_ms = (double)cxlBenchPercentile(ctx->latencies_us, count, 95) / 1000.0;
    double p99_ms = (double)cxlBenchPercentile(ctx->latencies_us, count, 99) / 1000.0;
    double max_ms = (double)ctx->latencies_us[count - 1] / 1000.0;

    if (config.csv) {
        printf("\"%s\",\"%.2f\",\"%.3f\",\"%.3f\",\"%.3f\",\"%.3f\",\"%.3f\",\"%.3f\"\n",
               title, rps, avg_ms, min_ms, p50_ms, p95_ms, p99_ms, max_ms);
    } else if (config.quiet) {
        printf("%s: %.2f requests per second\n", title, rps);
    } else {
        printf("====== %s ======\n", title);
        printf("  mode: %s\n", cxlBenchModeName());
        printf("  requests: %d\n", count);
        printf("  throughput: %.2f requests per second\n", rps);
        printf("  latency ms: avg %.3f min %.3f p50 %.3f p95 %.3f p99 %.3f max %.3f\n",
               avg_ms, min_ms, p50_ms, p95_ms, p99_ms, max_ms);
    }
}

static const char *cxlYcsbWorkloadName(void) {
    static const char *names[] = {"A", "B", "C", "D", "E", "F"};
    return names[config.ycsb_workload];
}

static const char *cxlYcsbPhaseName(int load_phase) {
    return load_phase ? "LOAD" : "RUN";
}

static const char *ycsbTransportName(void) {
    return config.cxl_enabled ? cxlBenchModeName() : "TCP";
}

static const char *cxlYcsbOpName(int op) {
    static const char *names[] = {"read", "update", "insert", "scan", "rmw"};
    return names[op];
}

static double cxlYcsbZeta(unsigned long long n, double theta) {
    double sum = 0.0;
    for (unsigned long long i = 1; i <= n; i++)
        sum += 1.0 / pow((double)i, theta);
    return sum;
}

static void cxlYcsbZipfInit(cxlYcsbZipf *z, unsigned long long items,
                            double theta) {
    if (items < 1) items = 1;
    z->items = items;
    z->theta = theta;
    z->zeta2theta = cxlYcsbZeta(2, theta);
    z->alpha = 1.0 / (1.0 - theta);
    z->zetan = cxlYcsbZeta(items, theta);
    if (items <= 1) {
        z->eta = 0.0;
    } else {
        z->eta = (1.0 - pow(2.0 / (double)items, 1.0 - theta)) /
                 (1.0 - z->zeta2theta / z->zetan);
    }
}

static uint64_t cxlYcsbRand64(uint64_t *state) {
    uint64_t x = *state;
    if (x == 0) x = 88172645463325252ULL;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static double cxlYcsbRandDouble(uint64_t *state) {
    return (double)(cxlYcsbRand64(state) >> 11) *
           (1.0 / 9007199254740992.0);
}

static unsigned long long cxlYcsbFnv64(unsigned long long value) {
    uint64_t hash = 1469598103934665603ULL;
    for (int i = 0; i < 8; i++) {
        hash ^= (uint8_t)((value >> (i * 8)) & 0xffU);
        hash *= 1099511628211ULL;
    }
    return hash;
}

static unsigned long long cxlYcsbZipfNext(cxlYcsbZipf *z, uint64_t *rng) {
    if (z->items <= 1) return 0;
    double u = cxlYcsbRandDouble(rng);
    double uz = u * z->zetan;
    if (uz < 1.0) return 0;
    if (uz < 1.0 + pow(0.5, z->theta)) return 1;
    unsigned long long ret =
        (unsigned long long)((double)z->items *
                             pow(z->eta * u - z->eta + 1.0, z->alpha));
    return ret < z->items ? ret : z->items - 1;
}

static int cxlYcsbEffectiveRequestDist(void) {
    if (config.ycsb_request_distribution != CXL_YCSB_DIST_AUTO)
        return config.ycsb_request_distribution;
    if (config.ycsb_workload == CXL_YCSB_WORKLOAD_D)
        return CXL_YCSB_DIST_LATEST;
    return CXL_YCSB_DIST_ZIPFIAN;
}

static unsigned long long cxlYcsbCurrentKeyLimit(cxlBenchCtx *ctx) {
    unsigned long long limit = ctx->ycsb_next_insert_id;
    if (limit == 0) limit = config.ycsb_record_count;
    return limit ? limit : 1;
}

static unsigned long long cxlYcsbChooseKeyId(cxlBenchCtx *ctx, int latest,
                                             uint64_t *rng) {
    unsigned long long limit = cxlYcsbCurrentKeyLimit(ctx);
    int dist = latest ? CXL_YCSB_DIST_LATEST : cxlYcsbEffectiveRequestDist();

    if (dist == CXL_YCSB_DIST_UNIFORM)
        return cxlYcsbRand64(rng) % limit;

    unsigned long long raw = cxlYcsbZipfNext(&ycsb_key_zipf, rng);
    raw %= limit;
    if (dist == CXL_YCSB_DIST_LATEST)
        return limit - raw - 1;
    return cxlYcsbFnv64(raw) % limit;
}

static uint16_t cxlYcsbChooseScanLength(uint64_t *rng) {
    unsigned max_len = (unsigned)config.ycsb_max_scan_length;
    if (max_len == 0) max_len = 1;
    if (config.ycsb_scan_length_distribution == CXL_YCSB_DIST_ZIPFIAN) {
        unsigned long long raw = cxlYcsbZipfNext(&ycsb_scan_zipf, rng);
        return (uint16_t)((raw % max_len) + 1U);
    }
    return (uint16_t)((cxlYcsbRand64(rng) % max_len) + 1U);
}

static int cxlYcsbFormatKey(unsigned long long key_id, char *buf,
                            size_t buf_len) {
    int len = snprintf(buf, buf_len, "%s%0*llu", config.ycsb_key_prefix,
                       config.ycsb_key_width, key_id);
    if (len <= 0 || len >= (int)buf_len || len > 255)
        return C_ERR;
    return len;
}

static int cxlYcsbBuildCxlRequest(cxlBenchCtx *ctx, int cxl_op,
                                  unsigned long long key_id,
                                  uint16_t scan_len, uint8_t *buf,
                                  uint32_t *len_out) {
    char keybuf[256];
    int key_len = cxlYcsbFormatKey(key_id, keybuf, sizeof(keybuf));
    if (key_len == C_ERR) return C_ERR;

    if (cxl_op == CXL_OP_SET) {
        return cxlBenchBuildRawRequest(CXL_OP_SET, keybuf, key_len,
                                       ctx->value, (uint16_t)ctx->value_len,
                                       buf, len_out);
    }
    if (cxl_op == CXL_OP_SCAN) {
        return cxlBenchBuildRawRequest(CXL_OP_SCAN, keybuf, key_len,
                                       NULL, scan_len, buf, len_out);
    }
    return cxlBenchBuildRawRequest(CXL_OP_GET, keybuf, key_len,
                                   NULL, 0, buf, len_out);
}

static int cxlYcsbChooseRunOperation(uint64_t *rng) {
    double p = cxlYcsbRandDouble(rng);
    switch (config.ycsb_workload) {
    case CXL_YCSB_WORKLOAD_A:
        return p < 0.5 ? CXL_YCSB_OP_READ : CXL_YCSB_OP_UPDATE;
    case CXL_YCSB_WORKLOAD_B:
        return p < 0.95 ? CXL_YCSB_OP_READ : CXL_YCSB_OP_UPDATE;
    case CXL_YCSB_WORKLOAD_C:
        return CXL_YCSB_OP_READ;
    case CXL_YCSB_WORKLOAD_D:
        return p < 0.95 ? CXL_YCSB_OP_READ : CXL_YCSB_OP_INSERT;
    case CXL_YCSB_WORKLOAD_E:
        return p < 0.95 ? CXL_YCSB_OP_SCAN : CXL_YCSB_OP_INSERT;
    case CXL_YCSB_WORKLOAD_F:
        return p < 0.5 ? CXL_YCSB_OP_READ : CXL_YCSB_OP_RMW;
    default:
        return CXL_YCSB_OP_READ;
    }
}

static int cxlYcsbFirstCxlOp(int logical_op) {
    switch (logical_op) {
    case CXL_YCSB_OP_UPDATE:
    case CXL_YCSB_OP_INSERT:
        return CXL_OP_SET;
    case CXL_YCSB_OP_SCAN:
        return CXL_OP_SCAN;
    default:
        return CXL_OP_GET;
    }
}

static void cxlYcsbCountCxlRequest(cxlBenchCtx *ctx, int cxl_op) {
    if (cxl_op == CXL_OP_GET)
        __sync_fetch_and_add(&ctx->ycsb_cxl_gets, 1);
    else if (cxl_op == CXL_OP_SET)
        __sync_fetch_and_add(&ctx->ycsb_cxl_sets, 1);
    else if (cxl_op == CXL_OP_SCAN)
        __sync_fetch_and_add(&ctx->ycsb_cxl_scans, 1);
}

static int cxlYcsbBuildPending(cxlBenchCtx *ctx, int request_id,
                               uint64_t *rng, cxlYcsbPending *pending) {
    memset(pending, 0, sizeof(*pending));
    if (ctx->ycsb_load_phase) {
        pending->logical_op = CXL_YCSB_OP_INSERT;
        pending->key_id = (unsigned long long)request_id;
        return C_OK;
    }

    int op = cxlYcsbChooseRunOperation(rng);
    pending->logical_op = op;
    if (op == CXL_YCSB_OP_INSERT) {
        pending->key_id =
            __sync_fetch_and_add(&ctx->ycsb_next_insert_id, 1ULL);
    } else {
        int latest = config.ycsb_workload == CXL_YCSB_WORKLOAD_D &&
                     op == CXL_YCSB_OP_READ;
        pending->key_id = cxlYcsbChooseKeyId(ctx, latest, rng);
    }
    if (op == CXL_YCSB_OP_SCAN)
        pending->scan_len = cxlYcsbChooseScanLength(rng);
    return C_OK;
}

static void cxlYcsbRecordLatency(cxlBenchCtx *ctx, int logical_op,
                                 long long latency) {
    cxlYcsbOpStats *stats = &ycsb_stats[logical_op];
    int idx = __sync_fetch_and_add(&stats->count, 1);
    if (idx < ctx->ycsb_target_ops)
        stats->latencies_us[idx] = latency;
    __sync_fetch_and_add(&stats->total_latency_us, latency);
    __sync_fetch_and_add(&ctx->finished, 1);
}

static int cxlYcsbSendOne(cxlBenchCtx *ctx, int ring_idx, uint32_t cid,
                          int cxl_op, cxlYcsbPending *pending,
                          uint8_t *req) {
    uint32_t req_len = 0;
    if (cxlYcsbBuildCxlRequest(ctx, cxl_op, pending->key_id,
                               pending->scan_len, req, &req_len) != C_OK)
        return C_ERR;
    if (cxlBenchSendRequest(ctx, ring_idx, cid, req, req_len) != C_OK)
        return C_ERR;
    cxlYcsbCountCxlRequest(ctx, cxl_op);
    return C_OK;
}

static void *cxlYcsbThreadMain(void *argptr) {
    cxlBenchThreadArg *arg = argptr;
    cxlBenchCtx *ctx = arg->ctx;
    int ring_idx = arg->index % ctx->ring_count;
    uint32_t cid = (uint32_t)arg->index + 1U;
    int pipeline = config.ycsb_workload == CXL_YCSB_WORKLOAD_F ?
        1 : config.pipeline;
    uint64_t rng = config.ycsb_seed ?
        config.ycsb_seed + (uint64_t)arg->index * 0x9e3779b97f4a7c15ULL :
        (uint64_t)ustime() ^ ((uint64_t)getpid() << 32) ^
            ((uint64_t)arg->index + 1U);
    uint8_t req[CXL_RING_MAX_PAYLOAD];
    cxlYcsbPending *pending = zmalloc(sizeof(*pending) * pipeline);

    while (!ctx->errors) {
        int batch = 0;
        for (; batch < pipeline; batch++) {
            int request_id = __sync_fetch_and_add(&ctx->issued, 1);
            if (request_id >= ctx->ycsb_target_ops) break;
            if (cxlYcsbBuildPending(ctx, request_id, &rng,
                                    &pending[batch]) != C_OK) {
                ctx->errors = 1;
                break;
            }
            int cxl_op = cxlYcsbFirstCxlOp(pending[batch].logical_op);
            pending[batch].start_us = ustime();
            if (cxlYcsbSendOne(ctx, ring_idx, cid, cxl_op,
                               &pending[batch], req) != C_OK) {
                ctx->errors = 1;
                break;
            }
        }
        if (batch == 0 || ctx->errors) break;

        for (int i = 0; i < batch; i++) {
            int status = 0;
            uint16_t value_len = 0;
            if (cxlBenchRecvResponse(ctx, ring_idx, cid,
                                     &status, &value_len) != C_OK) {
                ctx->errors = 1;
                break;
            }
            if (status == CXL_STATUS_ERR) {
                ctx->errors = 1;
                break;
            }
            if (pending[i].logical_op == CXL_YCSB_OP_RMW) {
                if (cxlYcsbSendOne(ctx, ring_idx, cid, CXL_OP_SET,
                                   &pending[i], req) != C_OK ||
                    cxlBenchRecvResponse(ctx, ring_idx, cid,
                                         &status, &value_len) != C_OK ||
                    status == CXL_STATUS_ERR) {
                    ctx->errors = 1;
                    break;
                }
            }
            long long latency = ustime() - pending[i].start_us;
            cxlYcsbRecordLatency(ctx, pending[i].logical_op, latency);
        }
    }
    zfree(pending);
    return NULL;
}

static void cxlRunWorkerGroup(cxlBenchCtx *ctx, int workers,
                              void *(*worker_main)(void *),
                              const char *label) {
    pthread_t tids[MAX_THREADS];
    cxlBenchThreadArg args[MAX_THREADS];
    int first_pthread = config.threads_use_main ? 1 : 0;

    for (int i = 0; i < workers; i++) {
        args[i].ctx = ctx;
        args[i].index = i;
    }
    for (int i = first_pthread; i < workers; i++) {
        if (pthread_create(&tids[i], NULL, worker_main, &args[i]) != 0) {
            fprintf(stderr, "%s: pthread_create failed\n", label);
            ctx->errors = 1;
            workers = i;
            break;
        }
    }
    if (config.threads_use_main && workers > 0)
        worker_main(&args[0]);
    for (int i = first_pthread; i < workers; i++)
        pthread_join(tids[i], NULL);
}

static void cxlYcsbFreePhaseStats(void) {
    for (int i = 0; i < CXL_YCSB_OP_MAX; i++) {
        if (ycsb_stats[i].latencies_us != NULL) {
            zfree(ycsb_stats[i].latencies_us);
            ycsb_stats[i].latencies_us = NULL;
        }
        ycsb_stats[i].count = 0;
        ycsb_stats[i].total_latency_us = 0;
    }
}

static int cxlYcsbInitPhaseStats(int target_ops) {
    cxlYcsbFreePhaseStats();
    for (int i = 0; i < CXL_YCSB_OP_MAX; i++) {
        ycsb_stats[i].latencies_us = zcalloc(sizeof(long long) * target_ops);
        if (ycsb_stats[i].latencies_us == NULL) {
            cxlYcsbFreePhaseStats();
            return C_ERR;
        }
    }
    return C_OK;
}

static void cxlYcsbReportPhase(cxlBenchCtx *ctx, const char *phase,
                               long long start_us, long long end_us) {
    double seconds = (double)(end_us - start_us) / 1000000.0;
    if (seconds <= 0.0) seconds = 0.000001;
    int total = ctx->finished;
    long long total_latency = 0;
    for (int i = 0; i < CXL_YCSB_OP_MAX; i++)
        total_latency += ycsb_stats[i].total_latency_us;

    if (!config.csv && !config.quiet) {
        printf("====== YCSB-%s-%s-%s ======\n",
               cxlYcsbWorkloadName(), ycsbTransportName(), phase);
        printf("  logical operations: %d\n", total);
        printf("  throughput: %.2f operations per second\n",
               (double)total / seconds);
        printf("  latency ms: avg %.3f\n",
               total ? ((double)total_latency / (double)total) / 1000.0 : 0.0);
        printf("  transport requests: get=%lld set=%lld scan=%lld\n",
               ctx->ycsb_cxl_gets, ctx->ycsb_cxl_sets,
               ctx->ycsb_cxl_scans);
    } else if (!config.csv) {
        printf("YCSB-%s-%s-%s: %.2f operations per second\n",
               cxlYcsbWorkloadName(), phase, ycsbTransportName(),
               (double)total / seconds);
    }

    for (int op = 0; op < CXL_YCSB_OP_MAX; op++) {
        cxlYcsbOpStats *stats = &ycsb_stats[op];
        int count = stats->count;
        if (count <= 0) continue;
        qsort(stats->latencies_us, count, sizeof(long long), cmpLongLong);
        double rps = (double)count / seconds;
        double avg_ms =
            ((double)stats->total_latency_us / (double)count) / 1000.0;
        double min_ms = (double)stats->latencies_us[0] / 1000.0;
        double p50_ms =
            (double)cxlBenchPercentile(stats->latencies_us, count, 50) /
            1000.0;
        double p95_ms =
            (double)cxlBenchPercentile(stats->latencies_us, count, 95) /
            1000.0;
        double p99_ms =
            (double)cxlBenchPercentile(stats->latencies_us, count, 99) /
            1000.0;
        double max_ms = (double)stats->latencies_us[count - 1] / 1000.0;
        if (config.csv) {
            printf("\"%s\",\"%s\",\"%d\",\"%.2f\",\"%.3f\",\"%.3f\","
                   "\"%.3f\",\"%.3f\",\"%.3f\",\"%.3f\",\"%lld\","
                   "\"%lld\",\"%lld\"\n",
                   phase, cxlYcsbOpName(op), count, rps, avg_ms, min_ms,
                   p50_ms, p95_ms, p99_ms, max_ms, ctx->ycsb_cxl_gets,
                   ctx->ycsb_cxl_sets, ctx->ycsb_cxl_scans);
        } else if (!config.quiet) {
            printf("  %-6s count=%d rps=%.2f latency_ms avg %.3f min %.3f "
                   "p50 %.3f p95 %.3f p99 %.3f max %.3f\n",
                   cxlYcsbOpName(op), count, rps, avg_ms, min_ms, p50_ms,
                   p95_ms, p99_ms, max_ms);
        }
    }
}

static int cxlYcsbRunPhase(cxlBenchCtx *ctx, int load_phase, int target_ops) {
    if (target_ops <= 0) return C_OK;
    if (cxlYcsbInitPhaseStats(target_ops) != C_OK) {
        fprintf(stderr, "YCSB benchmark: failed to allocate latency stats\n");
        return 1;
    }
    ctx->issued = 0;
    ctx->finished = 0;
    ctx->errors = 0;
    ctx->ycsb_target_ops = target_ops;
    ctx->ycsb_load_phase = load_phase;
    ctx->ycsb_cxl_gets = 0;
    ctx->ycsb_cxl_sets = 0;
    ctx->ycsb_cxl_scans = 0;

    int workers = config.num_threads > 0 ? config.num_threads : config.numclients;
    if (workers <= 0) workers = 1;
    if (workers > MAX_THREADS) workers = MAX_THREADS;

    long long start_us = ustime();
    cxlRunWorkerGroup(ctx, workers, cxlYcsbThreadMain, "YCSB benchmark");
    long long end_us = ustime();

    cxlYcsbReportPhase(ctx, cxlYcsbPhaseName(load_phase), start_us, end_us);
    int failed = ctx->errors || ctx->finished < target_ops;
    if (failed) {
        fprintf(stderr, "YCSB benchmark: completed %d/%d %s operations%s\n",
                ctx->finished, target_ops, cxlYcsbPhaseName(load_phase),
                ctx->errors ? " with errors" : "");
    }
    cxlYcsbFreePhaseStats();
    return failed ? 1 : 0;
}

static int cxlYcsbPrepareConfig(void) {
    if (config.ycsb_record_count == 0)
        config.ycsb_record_count = (unsigned long long)config.requests;
    if (config.ycsb_operation_count == 0)
        config.ycsb_operation_count = (unsigned long long)config.requests;
    if (!config.ycsb_insert_start_set)
        config.ycsb_insert_start = config.ycsb_record_count;
    if (!config.datasize_set) {
        unsigned long long size =
            (unsigned long long)config.ycsb_field_count *
            (unsigned long long)config.ycsb_field_length;
        if (size == 0 || size > INT_MAX) return C_ERR;
        config.datasize = (int)size;
    }
    if (config.ycsb_record_count == 0 ||
        config.ycsb_operation_count == 0 ||
        config.ycsb_record_count > INT_MAX ||
        config.ycsb_operation_count > INT_MAX ||
        config.ycsb_insert_start > ULLONG_MAX - config.ycsb_operation_count ||
        config.datasize <= 0 || config.datasize > UINT16_MAX)
        return C_ERR;
    if (config.pipeline >= (int)CXL_RING_QUEUE_CAPACITY)
        return C_ERR;

    unsigned long long zipf_items =
        config.ycsb_insert_start + config.ycsb_operation_count + 1ULL;
    cxlYcsbZipfInit(&ycsb_key_zipf, zipf_items, config.ycsb_zipf_theta);
    cxlYcsbZipfInit(&ycsb_scan_zipf,
                    (unsigned long long)config.ycsb_max_scan_length,
                    config.ycsb_zipf_theta);
    config.requests = (int)config.ycsb_operation_count;
    return C_OK;
}

static int tcpYcsbAppendCommand(redisContext *redis, cxlBenchCtx *ctx,
                                cxlYcsbPending *pending) {
    char keybuf[256];
    if (cxlYcsbFormatKey(pending->key_id, keybuf, sizeof(keybuf)) == C_ERR)
        return C_ERR;

    switch (pending->logical_op) {
    case CXL_YCSB_OP_UPDATE:
    case CXL_YCSB_OP_INSERT:
        if (redisAppendCommand(redis, "SET %s %b", keybuf,
                               ctx->value, (size_t)ctx->value_len) != REDIS_OK)
            return C_ERR;
        __sync_fetch_and_add(&ctx->ycsb_cxl_sets, 1);
        return C_OK;
    case CXL_YCSB_OP_SCAN: {
        sds cmd = sdsnew("MGET");
        size_t prefix_len = strlen(config.ycsb_key_prefix);
        unsigned long long start_id = pending->key_id;
        for (uint16_t i = 0; i < pending->scan_len; i++) {
            int key_len = snprintf(keybuf, sizeof(keybuf), "%s%0*llu",
                                   config.ycsb_key_prefix,
                                   config.ycsb_key_width, start_id + i);
            if (key_len <= 0 || key_len >= (int)sizeof(keybuf) ||
                key_len <= (int)prefix_len) {
                sdsfree(cmd);
                return C_ERR;
            }
            cmd = sdscatfmt(cmd, " %s", keybuf);
        }
        int rc = redisAppendCommand(redis, cmd);
        sdsfree(cmd);
        if (rc != REDIS_OK) return C_ERR;
        __sync_fetch_and_add(&ctx->ycsb_cxl_scans, 1);
        return C_OK;
    }
    default:
        if (redisAppendCommand(redis, "GET %s", keybuf) != REDIS_OK)
            return C_ERR;
        __sync_fetch_and_add(&ctx->ycsb_cxl_gets, 1);
        return C_OK;
    }
}

static int tcpYcsbDrainReply(redisContext *redis) {
    void *raw = NULL;
    int rc = redisGetReply(redis, &raw);
    redisReply *reply = rc == REDIS_OK ? raw : NULL;
    if (rc != REDIS_OK || reply == NULL) {
        if (reply != NULL) freeReplyObject(reply);
        return C_ERR;
    }
    int ok = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return ok ? C_OK : C_ERR;
}

static void *tcpYcsbThreadMain(void *argptr) {
    cxlBenchThreadArg *arg = argptr;
    cxlBenchCtx *ctx = arg->ctx;
    int pipeline = config.ycsb_workload == CXL_YCSB_WORKLOAD_F ?
        1 : config.pipeline;
    uint64_t rng = config.ycsb_seed ?
        config.ycsb_seed + (uint64_t)arg->index * 0x9e3779b97f4a7c15ULL :
        (uint64_t)ustime() ^ ((uint64_t)getpid() << 32) ^
            ((uint64_t)arg->index + 1U);
    cxlYcsbPending *pending = zmalloc(sizeof(*pending) * pipeline);
    redisContext *redis = getRedisContext(config.conn_info.hostip,
                                          config.conn_info.hostport,
                                          config.hostsocket);
    if (redis == NULL) {
        ctx->errors = 1;
        zfree(pending);
        return NULL;
    }

    while (!ctx->errors) {
        int batch = 0;
        for (; batch < pipeline; batch++) {
            int request_id = __sync_fetch_and_add(&ctx->issued, 1);
            if (request_id >= ctx->ycsb_target_ops) break;
            if (cxlYcsbBuildPending(ctx, request_id, &rng,
                                    &pending[batch]) != C_OK) {
                ctx->errors = 1;
                break;
            }
            pending[batch].start_us = ustime();
            if (tcpYcsbAppendCommand(redis, ctx, &pending[batch]) != C_OK) {
                ctx->errors = 1;
                break;
            }
        }
        if (batch == 0 || ctx->errors) break;

        for (int i = 0; i < batch; i++) {
            if (tcpYcsbDrainReply(redis) != C_OK) {
                ctx->errors = 1;
                break;
            }
            if (pending[i].logical_op == CXL_YCSB_OP_RMW) {
                pending[i].logical_op = CXL_YCSB_OP_UPDATE;
                if (tcpYcsbAppendCommand(redis, ctx, &pending[i]) != C_OK ||
                    tcpYcsbDrainReply(redis) != C_OK) {
                    ctx->errors = 1;
                    break;
                }
                pending[i].logical_op = CXL_YCSB_OP_RMW;
            }
            long long latency = ustime() - pending[i].start_us;
            cxlYcsbRecordLatency(ctx, pending[i].logical_op, latency);
        }
    }

    redisFree(redis);
    zfree(pending);
    return NULL;
}

static int tcpYcsbRunPhase(cxlBenchCtx *ctx, int load_phase, int target_ops) {
    if (target_ops <= 0) return C_OK;
    if (cxlYcsbInitPhaseStats(target_ops) != C_OK) {
        fprintf(stderr, "YCSB benchmark: failed to allocate latency stats\n");
        return 1;
    }
    ctx->issued = 0;
    ctx->finished = 0;
    ctx->errors = 0;
    ctx->ycsb_target_ops = target_ops;
    ctx->ycsb_load_phase = load_phase;
    ctx->ycsb_cxl_gets = 0;
    ctx->ycsb_cxl_sets = 0;
    ctx->ycsb_cxl_scans = 0;

    int workers = config.num_threads > 0 ? config.num_threads : config.numclients;
    if (workers <= 0) workers = 1;
    if (workers > MAX_THREADS) workers = MAX_THREADS;

    long long start_us = ustime();
    cxlRunWorkerGroup(ctx, workers, tcpYcsbThreadMain, "YCSB TCP benchmark");
    long long end_us = ustime();

    cxlYcsbReportPhase(ctx, cxlYcsbPhaseName(load_phase), start_us, end_us);
    int failed = ctx->errors || ctx->finished < target_ops;
    if (failed) {
        fprintf(stderr, "YCSB benchmark: completed %d/%d %s operations%s\n",
                ctx->finished, target_ops, cxlYcsbPhaseName(load_phase),
                ctx->errors ? " with errors" : "");
    }
    cxlYcsbFreePhaseStats();
    return failed ? 1 : 0;
}

static int tcpYcsbBenchmarkMain(void) {
    if (cxlYcsbPrepareConfig() != C_OK) {
        fprintf(stderr,
                "YCSB benchmark: invalid configuration or unsupported value size\n");
        return 1;
    }
    if (config.pipeline <= 0) config.pipeline = 1;

    cxlBenchCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = -1;
    ctx.value_len = config.datasize;
    ctx.value = zmalloc(ctx.value_len ? ctx.value_len : 1);
    genBenchmarkRandomData(ctx.value, ctx.value_len ? ctx.value_len : 1);

    if (config.csv) {
        printf("\"phase\",\"op\",\"operations\",\"rps\",\"avg_latency_ms\","
               "\"min_latency_ms\",\"p50_latency_ms\",\"p95_latency_ms\","
               "\"p99_latency_ms\",\"max_latency_ms\",\"tcp_gets\","
               "\"tcp_sets\",\"tcp_scans\"\n");
    }

    int rc = 0;
    if (config.ycsb_phase == CXL_YCSB_PHASE_LOAD ||
        config.ycsb_phase == CXL_YCSB_PHASE_LOAD_RUN) {
        ctx.ycsb_next_insert_id = config.ycsb_record_count;
        rc |= tcpYcsbRunPhase(&ctx, 1, (int)config.ycsb_record_count);
    }
    if (!rc && (config.ycsb_phase == CXL_YCSB_PHASE_RUN ||
                config.ycsb_phase == CXL_YCSB_PHASE_LOAD_RUN)) {
        ctx.ycsb_next_insert_id = config.ycsb_insert_start;
        rc |= tcpYcsbRunPhase(&ctx, 0, (int)config.ycsb_operation_count);
    }

    cxlBenchClose(&ctx);
    return rc;
}

static int cxlYcsbBenchmarkMain(void) {
    if (cxlYcsbPrepareConfig() != C_OK) {
        fprintf(stderr,
                "YCSB benchmark: invalid configuration or unsupported value size\n");
        return 1;
    }

    cxlBenchCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = -1;
    ctx.map_size = config.cxl_ring_map_size ?
        config.cxl_ring_map_size : CXL_BENCH_DEFAULT_MAP_SIZE;
    ctx.map_offset = config.cxl_ring_offset;
    ctx.region_base = config.cxl_ring_region_base;
    ctx.region_size = config.cxl_ring_region_size ?
        config.cxl_ring_region_size : cxlRingDefaultRegionSize();
    ctx.value_len = config.datasize;
    ctx.value = zmalloc(ctx.value_len ? ctx.value_len : 1);
    genBenchmarkRandomData(ctx.value, ctx.value_len ? ctx.value_len : 1);

    int workers = config.num_threads > 0 ? config.num_threads : config.numclients;
    if (workers <= 0) workers = 1;
    if (workers > MAX_THREADS) workers = MAX_THREADS;
    ctx.ring_count = config.cxl_ring_count > 0 ? config.cxl_ring_count : workers;
    if (ctx.ring_count < workers) {
        fprintf(stderr, "YCSB benchmark: --cxl-ring-count (%d) must be >= worker threads (%d)\n",
                ctx.ring_count, workers);
        cxlBenchClose(&ctx);
        return 1;
    }
    if (ctx.ring_count > MAX_THREADS) {
        fprintf(stderr, "YCSB benchmark: ring count too large (max %d)\n",
                MAX_THREADS);
        cxlBenchClose(&ctx);
        return 1;
    }
    if (cxlBenchOpenAndMap(&ctx) != C_OK) {
        cxlBenchClose(&ctx);
        return 1;
    }

    if (config.csv) {
        printf("\"phase\",\"op\",\"operations\",\"rps\",\"avg_latency_ms\","
               "\"min_latency_ms\",\"p50_latency_ms\",\"p95_latency_ms\","
               "\"p99_latency_ms\",\"max_latency_ms\",\"cxl_gets\","
               "\"cxl_sets\",\"cxl_scans\"\n");
    }

    int rc = 0;
    if (config.ycsb_phase == CXL_YCSB_PHASE_LOAD ||
        config.ycsb_phase == CXL_YCSB_PHASE_LOAD_RUN) {
        ctx.ycsb_next_insert_id = config.ycsb_record_count;
        rc |= cxlYcsbRunPhase(&ctx, 1, (int)config.ycsb_record_count);
    }
    if (!rc && (config.ycsb_phase == CXL_YCSB_PHASE_RUN ||
                config.ycsb_phase == CXL_YCSB_PHASE_LOAD_RUN)) {
        ctx.ycsb_next_insert_id = config.ycsb_insert_start;
        rc |= cxlYcsbRunPhase(&ctx, 0, (int)config.ycsb_operation_count);
    }

    cxlBenchClose(&ctx);
    return rc;
}

static int cxlBenchmarkRunOne(const char *name, int op) {
    cxlBenchCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = -1;
    ctx.op = op;
    ctx.map_size = config.cxl_ring_map_size ?
        config.cxl_ring_map_size : CXL_BENCH_DEFAULT_MAP_SIZE;
    ctx.map_offset = config.cxl_ring_offset;
    ctx.region_base = config.cxl_ring_region_base;
    ctx.region_size = config.cxl_ring_region_size ?
        config.cxl_ring_region_size : cxlRingDefaultRegionSize();
    int workers = config.num_threads > 0 ? config.num_threads : config.numclients;
    if (workers <= 0) workers = 1;
    if (workers > MAX_THREADS) workers = MAX_THREADS;
    ctx.ring_count = config.cxl_ring_count > 0 ? config.cxl_ring_count : workers;
    if (ctx.ring_count < workers) {
        fprintf(stderr, "CXL benchmark: --cxl-ring-count (%d) must be >= worker threads (%d)\n",
                ctx.ring_count, workers);
        return 1;
    }
    if (ctx.ring_count > MAX_THREADS) {
        fprintf(stderr, "CXL benchmark: ring count too large (max %d)\n", MAX_THREADS);
        return 1;
    }
    if (config.datasize > UINT16_MAX) {
        fprintf(stderr, "CXL benchmark: -d must be <= %u for this binary protocol\n",
                (unsigned)UINT16_MAX);
        return 1;
    }
    if (config.pipeline >= (int)CXL_RING_QUEUE_CAPACITY) {
        fprintf(stderr, "CXL benchmark: -P must be smaller than ring capacity (%u)\n",
                (unsigned)CXL_RING_QUEUE_CAPACITY);
        return 1;
    }
    ctx.value_len = config.datasize;
    ctx.value = zmalloc(ctx.value_len ? ctx.value_len : 1);
    memset(ctx.value, 'x', ctx.value_len ? ctx.value_len : 1);
    ctx.latencies_us = zcalloc(sizeof(long long) * config.requests);

    if (cxlBenchOpenAndMap(&ctx) != C_OK) {
        cxlBenchClose(&ctx);
        return 1;
    }

    ctx.start_us = ustime();
    cxlRunWorkerGroup(&ctx, workers, cxlBenchThreadMain, "CXL benchmark");
    ctx.end_us = ustime();

    char title[128];
    snprintf(title, sizeof(title), "%s-CXL-%s", name, cxlBenchModeName());
    cxlBenchReport(title, &ctx);
    int failed = ctx.errors || ctx.finished < config.requests;
    if (failed) {
        fprintf(stderr, "CXL benchmark: completed %d/%d requests%s\n",
                ctx.finished, config.requests, ctx.errors ? " with errors" : "");
    }
    cxlBenchClose(&ctx);
    return failed ? 1 : 0;
}

static int redisBenchmarkTouchClientDone(int rc) {
    if (config.gem5_client_sync_dir == NULL || config.gem5_client_id < 0)
        return C_OK;

    char dirbuf[PATH_MAX];
    snprintf(dirbuf, sizeof(dirbuf), "%s", config.gem5_client_sync_dir);
    size_t dirlen = strlen(dirbuf);
    while (dirlen > 1 && dirbuf[dirlen - 1] == '/')
        dirbuf[--dirlen] = '\0';
    for (char *p = dirbuf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(dirbuf, 0700) != 0 && errno != EEXIST)
            return C_ERR;
        *p = '/';
    }
    if (mkdir(dirbuf, 0700) != 0 && errno != EEXIST)
        return C_ERR;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/client_%d.done",
             config.gem5_client_sync_dir, config.gem5_client_id);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return C_ERR;
    char buf[64];
    int len = snprintf(buf, sizeof(buf), "%d\n", rc);
    if (write(fd, buf, len) != len) {
        close(fd);
        return C_ERR;
    }
    close(fd);
    return C_OK;
}

static int redisBenchmarkWaitAllClients(void) {
    if (config.gem5_client_sync_dir == NULL || config.gem5_client_count <= 0)
        return C_OK;

    long long deadline = ustime() +
        (long long)config.gem5_client_sync_timeout_ms * 1000LL;
    while (1) {
        int complete = 1;
        for (int i = 0; i < config.gem5_client_count; i++) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/client_%d.done",
                     config.gem5_client_sync_dir, i);
            struct stat st;
            if (stat(path, &st) != 0) {
                complete = 0;
                break;
            }
        }
        if (complete) return C_OK;
        if (config.gem5_client_sync_timeout_ms > 0 && ustime() >= deadline)
            return C_ERR;
        sched_yield();
    }
}

static void redisBenchmarkShutdownServer(void) {
    redisContext *ctx = getRedisContext(config.conn_info.hostip,
                                        config.conn_info.hostport,
                                        config.hostsocket);
    if (ctx == NULL) return;
    redisReply *reply = redisCommand(ctx, "SHUTDOWN NOSAVE");
    if (reply != NULL) freeReplyObject(reply);
    redisFree(ctx);
}

static void redisBenchmarkShutdownServerOverCxl(void) {
    cxlBenchCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd = -1;
    ctx.map_size = config.cxl_ring_map_size ?
        config.cxl_ring_map_size : CXL_BENCH_DEFAULT_MAP_SIZE;
    ctx.map_offset = config.cxl_ring_offset;
    ctx.region_base = config.cxl_ring_region_base;
    ctx.region_size = config.cxl_ring_region_size ?
        config.cxl_ring_region_size : cxlRingDefaultRegionSize();
    ctx.ring_count = config.cxl_ring_count > 0 ? config.cxl_ring_count : 1;
    if (ctx.ring_count > MAX_THREADS)
        ctx.ring_count = MAX_THREADS;

    if (cxlBenchOpenAndMap(&ctx) == C_OK) {
        uint32_t cid = (uint32_t)(config.gem5_client_id >= 0 ?
                                  config.gem5_client_id + 1 : 1);
        (void)cxlRingQueueSend(&ctx.rings[0].q21, cid, CXL_RING_MSG_CLOSE,
                               0U, NULL, 0U);
    }
    cxlBenchClose(&ctx);
}

static int redisBenchmarkPostRun(int rc) {
    if (redisBenchmarkTouchClientDone(rc) != C_OK && rc == 0)
        rc = 1;

    if (config.shutdown_server_after &&
        (config.gem5_client_id <= 0 || config.gem5_client_count <= 1)) {
        if (redisBenchmarkWaitAllClients() != C_OK && rc == 0)
            rc = 1;
        if (config.cxl_enabled)
            redisBenchmarkShutdownServerOverCxl();
        else
            redisBenchmarkShutdownServer();
    }

    return rc;
}

static int cxlBenchmarkMain(int argc, char **argv) {
    if (config.idlemode) {
        fprintf(stderr, "CXL benchmark mode does not support idle mode.\n");
        return 1;
    }
    if (config.ycsb_enabled) {
        if (argc > 0) {
            fprintf(stderr,
                    "YCSB benchmark mode does not accept COMMAND ARGS.\n");
            return 1;
        }
        return cxlYcsbBenchmarkMain();
    }
    if (config.pipeline <= 0) config.pipeline = 1;
    if (config.requests <= 0) config.requests = 1;

    if (config.csv) {
        printf("\"test\",\"rps\",\"avg_latency_ms\",\"min_latency_ms\",\"p50_latency_ms\",\"p95_latency_ms\",\"p99_latency_ms\",\"max_latency_ms\"\n");
    }

    if (argc > 0) {
        if (!strcasecmp(argv[0], "set"))
            return cxlBenchmarkRunOne("SET", CXL_OP_SET);
        if (!strcasecmp(argv[0], "get"))
            return cxlBenchmarkRunOne("GET", CXL_OP_GET);
        fprintf(stderr, "CXL benchmark mode supports only GET and SET command tests.\n");
        return 1;
    }

    int rc = 0;
    if (test_is_selected("set"))
        rc |= cxlBenchmarkRunOne("SET", CXL_OP_SET);
    if (test_is_selected("get"))
        rc |= cxlBenchmarkRunOne("GET", CXL_OP_GET);
    if (!test_is_selected("set") && !test_is_selected("get")) {
        fprintf(stderr, "CXL benchmark mode only implements -t set,get.\n");
        rc = 1;
    }
    return rc;
}

int main(int argc, char **argv) {
    int i;
    char *data, *cmd, *tag;
    int len;

    client c;

    srandom(time(NULL) ^ getpid());
    init_genrand64(ustime() ^ getpid());
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    memset(&config.sslconfig, 0, sizeof(config.sslconfig));
    config.numclients = 50;
    config.requests = 100000;
    config.liveclients = 0;
    config.el = aeCreateEventLoop(1024*10);
    if (redisGem5SeDontWaitEnabled())
        aeSetDontWait(config.el, 1);
    aeCreateTimeEvent(config.el,1,showThroughput,NULL,NULL);
    config.keepalive = 1;
    config.datasize = 3;
    config.datasize_set = 0;
    config.pipeline = 1;
    config.randomkeys = 0;
    config.randomkeys_keyspacelen = 0;
    config.quiet = 0;
    config.csv = 0;
    config.loop = 0;
    config.idlemode = 0;
    config.clients = listCreate();
    config.conn_info.hostip = sdsnew("127.0.0.1");
    config.conn_info.hostport = 6379;
    config.hostsocket = NULL;
    config.tests = NULL;
    config.conn_info.input_dbnum = 0;
    config.stdinarg = 0;
    config.conn_info.auth = NULL;
    config.precision = DEFAULT_LATENCY_PRECISION;
    config.num_threads = 0;
    config.threads_use_main = 0;
    config.threads = NULL;
    config.cluster_mode = 0;
    config.cluster_node_count = 0;
    config.cluster_nodes = NULL;
    config.redis_config = NULL;
    config.is_fetching_slots = 0;
    config.is_updating_slots = 0;
    config.slots_last_update = 0;
    config.enable_tracking = 0;
    config.resp3 = 0;
    config.cxl_enabled = 0;
    config.cxl_mode = CXL_BENCH_MODE_NATIVE_SHM;
    config.cxl_paper_preset = 0;
    config.cxl_ring_path = NULL;
    config.cxl_ring_map_size = 0;
    config.cxl_ring_offset = 0;
    config.cxl_ring_region_base = 0;
    config.cxl_ring_region_size = 0;
    config.cxl_ring_count = 0;
    config.ycsb_enabled = 0;
    config.ycsb_transport = YCSB_TRANSPORT_AUTO;
    config.ycsb_workload = CXL_YCSB_WORKLOAD_A;
    config.ycsb_phase = CXL_YCSB_PHASE_LOAD_RUN;
    config.ycsb_record_count = 0;
    config.ycsb_operation_count = 0;
    config.ycsb_insert_start = 0;
    config.ycsb_insert_start_set = 0;
    config.ycsb_request_distribution = CXL_YCSB_DIST_AUTO;
    config.ycsb_scan_length_distribution = CXL_YCSB_DIST_UNIFORM;
    config.ycsb_max_scan_length = 100;
    config.ycsb_field_count = 10;
    config.ycsb_field_length = 100;
    config.ycsb_read_all_fields = 1;
    config.ycsb_seed = 0;
    config.ycsb_key_prefix = strdup("user");
    config.ycsb_key_width = 12;
    config.ycsb_zipf_theta = 0.99;
    config.server_ready_timeout_ms = 0;
    config.gem5_client_id = -1;
    config.gem5_client_count = 0;
    config.gem5_client_sync_timeout_ms = 600000;
    config.shutdown_server_after = 0;
    config.gem5_client_sync_dir = NULL;

    i = parseOptions(argc,argv);
    argc -= i;
    argv += i;

    tag = "";

#ifdef USE_OPENSSL
    if (config.tls) {
        cliSecureInit();
    }
#endif

    if (config.ycsb_enabled && !config.cxl_enabled) {
        int rc = tcpYcsbBenchmarkMain();
        return redisBenchmarkPostRun(rc);
    }

    if (config.cxl_enabled) {
        if (config.cxl_paper_preset && config.num_threads <= 0)
            config.num_threads = config.numclients;
        int rc = cxlBenchmarkMain(argc, argv);
        return redisBenchmarkPostRun(rc);
    }

    if (config.cluster_mode) {
        // We only include the slot placeholder {tag} if cluster mode is enabled
        tag = ":{tag}";

        /* Fetch cluster configuration. */
        if (!fetchClusterConfiguration() || !config.cluster_nodes) {
            if (!config.hostsocket) {
                fprintf(stderr, "Failed to fetch cluster configuration from "
                                "%s:%d\n", config.conn_info.hostip, config.conn_info.hostport);
            } else {
                fprintf(stderr, "Failed to fetch cluster configuration from "
                                "%s\n", config.hostsocket);
            }
            exit(1);
        }
        if (config.cluster_node_count <= 1) {
            fprintf(stderr, "Invalid cluster: %d node(s).\n",
                    config.cluster_node_count);
            exit(1);
        }
        printf("Cluster has %d master nodes:\n\n", config.cluster_node_count);
        int i = 0;
        for (; i < config.cluster_node_count; i++) {
            clusterNode *node = config.cluster_nodes[i];
            if (!node) {
                fprintf(stderr, "Invalid cluster node #%d\n", i);
                exit(1);
            }
            printf("Master %d: ", i);
            if (node->name) printf("%s ", node->name);
            printf("%s:%d\n", node->ip, node->port);
            node->redis_config = getRedisConfig(node->ip, node->port, NULL);
            if (node->redis_config == NULL) {
                fprintf(stderr, "WARNING: Could not fetch node CONFIG %s:%d\n",
                        node->ip, node->port);
            }
        }
        printf("\n");
        /* Automatically set thread number to node count if not specified
         * by the user. */
        if (config.num_threads == 0)
            config.num_threads = config.cluster_node_count;
    } else {
        config.redis_config =
            getRedisConfig(config.conn_info.hostip, config.conn_info.hostport, config.hostsocket);
        if (config.redis_config == NULL) {
            fprintf(stderr, "WARNING: Could not fetch server CONFIG\n");
        }
    }
    if (config.num_threads > 0) {
        pthread_mutex_init(&(config.liveclients_mutex), NULL);
        pthread_mutex_init(&(config.is_updating_slots_mutex), NULL);
    }

    if (config.keepalive == 0) {
        fprintf(stderr,
                "WARNING: Keepalive disabled. You probably need "
                "'echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse' for Linux and "
                "'sudo sysctl -w net.inet.tcp.msl=1000' for Mac OS X in order "
                "to use a lot of clients/requests\n");
    }
    if (argc > 0 && config.tests != NULL) {
        fprintf(stderr, "WARNING: Option -t is ignored.\n");
    }

    if (config.idlemode) {
        printf("Creating %d idle connections and waiting forever (Ctrl+C when done)\n", config.numclients);
        int thread_id = -1, use_threads = (config.num_threads > 0);
        if (use_threads) {
            thread_id = 0;
            initBenchmarkThreads();
        }
        c = createClient("",0,NULL,thread_id); /* will never receive a reply */
        createMissingClients(c);
        if (use_threads) startBenchmarkThreads();
        else aeMain(config.el);
        /* and will wait for every */
    }
    if(config.csv){
        printf("\"test\",\"rps\",\"avg_latency_ms\",\"min_latency_ms\",\"p50_latency_ms\",\"p95_latency_ms\",\"p99_latency_ms\",\"max_latency_ms\"\n");
    }
    /* Run benchmark with command in the remainder of the arguments. */
    if (argc) {
        sds title = sdsnew(argv[0]);
        for (i = 1; i < argc; i++) {
            title = sdscatlen(title, " ", 1);
            title = sdscatlen(title, (char*)argv[i], strlen(argv[i]));
        }
        sds *sds_args = getSdsArrayFromArgv(argc, argv, 0);
        if (!sds_args) {
            fprintf(stderr, "Invalid quoted string\n");
            return 1;
        }
        if (config.stdinarg) {
            sds_args = sds_realloc(sds_args,(argc + 1) * sizeof(sds));
            sds_args[argc] = readArgFromStdin();
            argc++;
        }
        /* Setup argument length */
        size_t *argvlen = zmalloc(argc*sizeof(size_t));
        for (i = 0; i < argc; i++)
            argvlen[i] = sdslen(sds_args[i]);
        do {
            len = redisFormatCommandArgv(&cmd,argc,(const char**)sds_args,argvlen);
            // adjust the datasize to the parsed command
            config.datasize = len;
            benchmark(title,cmd,len);
            free(cmd);
        } while(config.loop);
        sdsfreesplitres(sds_args, argc);

        sdsfree(title);
        if (config.redis_config != NULL) freeRedisConfig(config.redis_config);
        zfree(argvlen);
        return 0;
    }

    /* Run default benchmark suite. */
    data = zmalloc(config.datasize+1);
    do {
        genBenchmarkRandomData(data, config.datasize);
        data[config.datasize] = '\0';

        if (test_is_selected("ping_inline") || test_is_selected("ping"))
            benchmark("PING_INLINE","PING\r\n",6);

        if (test_is_selected("ping_mbulk") || test_is_selected("ping")) {
            len = redisFormatCommand(&cmd,"PING");
            benchmark("PING_MBULK",cmd,len);
            free(cmd);
        }

        if (test_is_selected("set")) {
            len = redisFormatCommand(&cmd,"SET key%s:__rand_int__ %s",tag,data);
            benchmark("SET",cmd,len);
            free(cmd);
        }

        if (test_is_selected("get")) {
            len = redisFormatCommand(&cmd,"GET key%s:__rand_int__",tag);
            benchmark("GET",cmd,len);
            free(cmd);
        }

        if (test_is_selected("incr")) {
            len = redisFormatCommand(&cmd,"INCR counter%s:__rand_int__",tag);
            benchmark("INCR",cmd,len);
            free(cmd);
        }

        if (test_is_selected("lpush")) {
            len = redisFormatCommand(&cmd,"LPUSH mylist%s %s",tag,data);
            benchmark("LPUSH",cmd,len);
            free(cmd);
        }

        if (test_is_selected("rpush")) {
            len = redisFormatCommand(&cmd,"RPUSH mylist%s %s",tag,data);
            benchmark("RPUSH",cmd,len);
            free(cmd);
        }

        if (test_is_selected("lpop")) {
            len = redisFormatCommand(&cmd,"LPOP mylist%s",tag);
            benchmark("LPOP",cmd,len);
            free(cmd);
        }

        if (test_is_selected("rpop")) {
            len = redisFormatCommand(&cmd,"RPOP mylist%s",tag);
            benchmark("RPOP",cmd,len);
            free(cmd);
        }

        if (test_is_selected("sadd")) {
            len = redisFormatCommand(&cmd,
                "SADD myset%s element:__rand_int__",tag);
            benchmark("SADD",cmd,len);
            free(cmd);
        }

        if (test_is_selected("hset")) {
            len = redisFormatCommand(&cmd,
                "HSET myhash%s element:__rand_int__ %s",tag,data);
            benchmark("HSET",cmd,len);
            free(cmd);
        }

        if (test_is_selected("spop")) {
            len = redisFormatCommand(&cmd,"SPOP myset%s",tag);
            benchmark("SPOP",cmd,len);
            free(cmd);
        }

        if (test_is_selected("zadd")) {
            char *score = "0";
            if (config.randomkeys) score = "__rand_int__";
            len = redisFormatCommand(&cmd,
                "ZADD myzset%s %s element:__rand_int__",tag,score);
            benchmark("ZADD",cmd,len);
            free(cmd);
        }

        if (test_is_selected("zpopmin")) {
            len = redisFormatCommand(&cmd,"ZPOPMIN myzset%s",tag);
            benchmark("ZPOPMIN",cmd,len);
            free(cmd);
        }

        if (test_is_selected("lrange") ||
            test_is_selected("lrange_100") ||
            test_is_selected("lrange_300") ||
            test_is_selected("lrange_500") ||
            test_is_selected("lrange_600"))
        {
            len = redisFormatCommand(&cmd,"LPUSH mylist%s %s",tag,data);
            benchmark("LPUSH (needed to benchmark LRANGE)",cmd,len);
            free(cmd);
        }

        if (test_is_selected("lrange") || test_is_selected("lrange_100")) {
            len = redisFormatCommand(&cmd,"LRANGE mylist%s 0 99",tag);
            benchmark("LRANGE_100 (first 100 elements)",cmd,len);
            free(cmd);
        }

        if (test_is_selected("lrange") || test_is_selected("lrange_300")) {
            len = redisFormatCommand(&cmd,"LRANGE mylist%s 0 299",tag);
            benchmark("LRANGE_300 (first 300 elements)",cmd,len);
            free(cmd);
        }

        if (test_is_selected("lrange") || test_is_selected("lrange_500")) {
            len = redisFormatCommand(&cmd,"LRANGE mylist%s 0 499",tag);
            benchmark("LRANGE_500 (first 500 elements)",cmd,len);
            free(cmd);
        }

        if (test_is_selected("lrange") || test_is_selected("lrange_600")) {
            len = redisFormatCommand(&cmd,"LRANGE mylist%s 0 599",tag);
            benchmark("LRANGE_600 (first 600 elements)",cmd,len);
            free(cmd);
        }

        if (test_is_selected("mset")) {
            const char *cmd_argv[21];
            cmd_argv[0] = "MSET";
            sds key_placeholder = sdscatprintf(sdsnew(""),"key%s:__rand_int__",tag);
            for (i = 1; i < 21; i += 2) {
                cmd_argv[i] = key_placeholder;
                cmd_argv[i+1] = data;
            }
            len = redisFormatCommandArgv(&cmd,21,cmd_argv,NULL);
            benchmark("MSET (10 keys)",cmd,len);
            free(cmd);
            sdsfree(key_placeholder);
        }

        if (test_is_selected("xadd")) {
            len = redisFormatCommand(&cmd,"XADD mystream%s * myfield %s", tag, data);
            benchmark("XADD",cmd,len);
            free(cmd); 
        }        

        if (!config.csv) printf("\n");
    } while(config.loop);

    int rc = redisBenchmarkPostRun(0);

    zfree(data);
    freeCliConnInfo(config.conn_info);
    if (config.redis_config != NULL) freeRedisConfig(config.redis_config);

    return rc;
}
