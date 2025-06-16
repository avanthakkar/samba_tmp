#include "includes.h"
#include "system/time.h"
#include "lib/tevent/tevent.h"
#include "smbd/smbd.h"
#include "vfs_ceph.h"
#include "vfs_ceph_rate_limit.h"

#define TOKEN_REFILL_INTERVAL_MS 100
#define RATE_LIMIT_RETRY_INTERVAL_MS 100

void init_rate_limiter(struct rate_limiter *rl, double iops, double bw, bool enable)
{
    struct timeval now = timeval_current();

    rl->enabled = enable;
    rl->rate_iops = 0.1 * iops;
    rl->rate_bytes = 0.1 * bw;
    rl->burst_iops = iops;
    rl->burst_bytes = bw;
    rl->tokens_iops = rl->burst_iops;
    rl->tokens_bytes = rl->burst_bytes;
    rl->last_refill_iops = now;
    rl->last_refill_bw = now;
    rl->queue_head = rl->queue_tail = NULL;
    rl->timer = NULL;
}

void refill_tokens(struct rate_limiter *rl, int snum)
{
    if (!rl->enabled) return;

    struct timeval now = timeval_current();
    double elapsed_iops = timeval_elapsed(&rl->last_refill_iops, &now);
    double elapsed_bw = timeval_elapsed(&rl->last_refill_bw, &now);

    rl->tokens_iops += rl->rate_iops * elapsed_iops;
    rl->tokens_bytes += rl->rate_bytes * elapsed_bw;

    if (rl->tokens_iops > rl->burst_iops) rl->tokens_iops = rl->burst_iops;
    if (rl->tokens_bytes > rl->burst_bytes) rl->tokens_bytes = rl->burst_bytes;

    rl->last_refill_iops = now;
    rl->last_refill_bw = now;
}

static void rate_limit_timer_cb(struct tevent_context *ev, struct tevent_timer *te,
                                struct timeval t, void *private_data)
{
    struct rate_limiter *rl = talloc_get_type_abort(private_data, struct rate_limiter);
    struct tevent_req *req = rl->queue_head;

    if (!rl->enabled || req == NULL) return;

    refill_tokens(rl, SNUM(req->data));

    while (req != NULL) {
        struct rate_req_state *state = tevent_req_data(req, struct rate_req_state);
        if (rl->tokens_iops >= 1 && rl->tokens_bytes >= state->bytes) {
            rl->tokens_iops -= 1;
            rl->tokens_bytes -= state->bytes;

            struct tevent_req *next = tevent_req_next(req);
            DLIST_REMOVE(rl->queue_head, req);
            if (rl->queue_head == NULL) rl->queue_tail = NULL;

            tevent_req_done(req);
            req = next;
        } else {
            break;
        }
    }

    if (rl->queue_head != NULL) {
        struct timeval tv = timeval_current_ofs(0, RATE_LIMIT_RETRY_INTERVAL_MS);
        rl->timer = tevent_add_timer(ev, rl, tv, rate_limit_timer_cb, rl);
    } else {
        rl->timer = NULL;
    }
}

bool check_rate_limit(struct vfs_handle_struct *handle,
                      struct files_struct *fsp,
                      struct rate_limiter *rl,
                      size_t bytes,
                      struct tevent_req *req,
                      struct tevent_context *ev)
{
    if (!rl->enabled) return false;

    int snum = SNUM(handle->conn);
    refill_tokens(rl, snum);

    if (rl->tokens_iops >= 1 && rl->tokens_bytes >= bytes) {
        rl->tokens_iops -= 1;
        rl->tokens_bytes -= bytes;
        return false;
    }

    struct rate_req_state *state = tevent_req_data(req, struct rate_req_state);
    state->handle = handle;
    state->fsp = fsp;
    state->bytes = bytes;
    state->limiter = rl;

    DLIST_ADD_END(rl->queue_head, req, struct tevent_req *);
    if (rl->queue_tail == NULL) rl->queue_tail = req;

    if (!rl->timer) {
        struct timeval tv = timeval_current_ofs(0, RATE_LIMIT_RETRY_INTERVAL_MS);
        rl->timer = tevent_add_timer(ev, rl, tv, rate_limit_timer_cb, rl);
    }

    return true;
}
