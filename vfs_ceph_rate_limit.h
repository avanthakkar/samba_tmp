#ifndef __VFS_CEPH_RATE_LIMIT_H__
#define __VFS_CEPH_RATE_LIMIT_H__

#include "includes.h"
#include "system/time.h"
#include "lib/tevent/tevent.h"
#include "smbd/smbd.h"

#define TOKEN_REFILL_INTERVAL_MS 100
#define RATE_LIMIT_RETRY_INTERVAL_MS 100

enum io_op_type {
    IO_OP_READ = 0,
    IO_OP_WRITE = 1,
};

struct rate_limiter {
    bool enabled;
    double tokens_iops;
    double tokens_bytes;
    double rate_iops;
    double rate_bytes;
    double burst_iops;
    double burst_bytes;
    struct timeval last_refill_iops;
    struct timeval last_refill_bw;
    struct tevent_req *queue_head;
    struct tevent_req *queue_tail;
    struct tevent_timer *timer;
};

struct rate_req_state {
    struct vfs_handle_struct *handle;
    struct files_struct *fsp;
    size_t bytes;
    struct rate_limiter *limiter;
};

void init_rate_limiter(struct rate_limiter *rl, double iops, double bw, bool enable);
void refill_tokens(struct rate_limiter *rl, int snum);
bool check_rate_limit(struct vfs_handle_struct *handle,
                      struct files_struct *fsp,
                      struct rate_limiter *rl,
                      size_t bytes,
                      struct tevent_req *req,
                      struct tevent_context *ev);

#endif /* __VFS_CEPH_RATE_LIMIT_H__ */
