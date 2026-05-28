/* Select()-based ae.c module.
 *
 * Copyright (c) 2009-Present, Redis Ltd.
 * All rights reserved.
 *
 * Licensed under your choice of (a) the Redis Source Available License 2.0
 * (RSALv2); or (b) the Server Side Public License v1 (SSPLv1); or (c) the
 * GNU Affero General Public License v3 (AGPLv3).
 */


#include <sys/select.h>
#include <string.h>

typedef struct aeApiState {
    fd_set rfds, wfds;
    /* We need to have a copy of the fd sets as it's not safe to reuse
     * FD sets after select(). */
    fd_set _rfds, _wfds;
} aeApiState;

static int aeApiCreate(aeEventLoop *eventLoop) {
    aeApiState *state = zmalloc(sizeof(aeApiState));

    if (!state) return -1;
    FD_ZERO(&state->rfds);
    FD_ZERO(&state->wfds);
    eventLoop->apidata = state;
    return 0;
}

static int aeApiResize(aeEventLoop *eventLoop, int setsize) {
    AE_NOTUSED(eventLoop);
    /* Just ensure we have enough room in the fd_set type. */
    if (setsize >= FD_SETSIZE) return -1;
    return 0;
}

static void aeApiFree(aeEventLoop *eventLoop) {
    zfree(eventLoop->apidata);
}

static int aeApiAddEvent(aeEventLoop *eventLoop, int fd, int mask) {
    aeApiState *state = eventLoop->apidata;

    if (mask & AE_READABLE) FD_SET(fd,&state->rfds);
    if (mask & AE_WRITABLE) FD_SET(fd,&state->wfds);
    return 0;
}

static void aeApiDelEvent(aeEventLoop *eventLoop, int fd, int mask) {
    aeApiState *state = eventLoop->apidata;

    if (mask & AE_READABLE) FD_CLR(fd,&state->rfds);
    if (mask & AE_WRITABLE) FD_CLR(fd,&state->wfds);
}

static int aeApiPoll(aeEventLoop *eventLoop, struct timeval *tvp) {
#ifndef REDIS_GEM5_SE_SELECT
    aeApiState *state = eventLoop->apidata;
#endif
    int retval, j, numevents = 0;

#ifdef REDIS_GEM5_SE_SELECT
    int nfds = 0;
    for (j = 0; j <= eventLoop->maxfd; j++) {
        if (eventLoop->events[j].mask != AE_NONE)
            nfds++;
    }
    if (nfds == 0) return 0;

    struct pollfd *pfds = zmalloc(sizeof(*pfds) * nfds);
    int *target_fds = zmalloc(sizeof(*target_fds) * nfds);
    if (pfds == NULL || target_fds == NULL) {
        zfree(pfds);
        zfree(target_fds);
        return 0;
    }

    int idx = 0;
    for (j = 0; j <= eventLoop->maxfd; j++) {
        aeFileEvent *fe = &eventLoop->events[j];
        if (fe->mask == AE_NONE) continue;
        target_fds[idx] = j;
        pfds[idx].fd = j;
        pfds[idx].events = 0;
        pfds[idx].revents = 0;
        if (fe->mask & AE_READABLE) pfds[idx].events |= POLLIN;
        if (fe->mask & AE_WRITABLE) pfds[idx].events |= POLLOUT;
        idx++;
    }

    int timeout_ms = 0;
    if (tvp != NULL)
        timeout_ms = (int)(tvp->tv_sec * 1000 + tvp->tv_usec / 1000);
    retval = poll(pfds, nfds, timeout_ms);
    if (retval > 0) {
        for (idx = 0; idx < nfds; idx++) {
            int mask = 0;
            if (pfds[idx].revents & (POLLIN | POLLERR | POLLHUP))
                mask |= AE_READABLE;
            if (pfds[idx].revents & (POLLOUT | POLLERR | POLLHUP))
                mask |= AE_WRITABLE;
            if (mask == 0) continue;
            eventLoop->fired[numevents].fd = target_fds[idx];
            eventLoop->fired[numevents].mask = mask;
            numevents++;
        }
    } else if (retval == -1 && errno != EINTR) {
        panic("aeApiPoll: poll, %s", strerror(errno));
    }
    zfree(pfds);
    zfree(target_fds);
    return numevents;
#else
    memcpy(&state->_rfds,&state->rfds,sizeof(fd_set));
    memcpy(&state->_wfds,&state->wfds,sizeof(fd_set));

    retval = select(eventLoop->maxfd+1,
                &state->_rfds,&state->_wfds,NULL,tvp);
    if (retval > 0) {
        for (j = 0; j <= eventLoop->maxfd; j++) {
            int mask = 0;
            aeFileEvent *fe = &eventLoop->events[j];

            if (fe->mask == AE_NONE) continue;
            if (fe->mask & AE_READABLE && FD_ISSET(j,&state->_rfds))
                mask |= AE_READABLE;
            if (fe->mask & AE_WRITABLE && FD_ISSET(j,&state->_wfds))
                mask |= AE_WRITABLE;
            eventLoop->fired[numevents].fd = j;
            eventLoop->fired[numevents].mask = mask;
            numevents++;
        }
    } else if (retval == -1 && errno != EINTR) {
        panic("aeApiPoll: select, %s", strerror(errno));
    }

    return numevents;
#endif
}

static char *aeApiName(void) {
    return "select";
}
