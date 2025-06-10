#include "includes.h"
#include "smbd/smbd.h"
#include "lib/tevent/tevent.h"
#include "tevent_util.h"
#include "vfs_ceph.h"
#include "system/time.h"

struct rate_limiter {
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

static struct {
    struct rate_limiter read;
    struct rate_limiter write;
} *share_limiters = NULL;
static int num_shares = 0;

void smb_rate_limit_init_share(int snum,
                               uint32_t read_iops, uint32_t read_bw,
                               uint32_t write_iops, uint32_t write_bw)
{
    // Allocate the array on first use
    if (share_limiters == NULL) {
        num_shares = lp_numservices();  // total number of defined shares
        share_limiters = talloc_zero_array(NULL, typeof(*share_limiters), num_shares);
    }
    if (snum < 0 || snum >= num_shares || share_limiters == NULL) {
        return; // invalid share index
    }
    struct rate_limiter *rl_read = &share_limiters[snum].read;
    struct rate_limiter *rl_write = &share_limiters[snum].write;
    // Initialize read limiter
    rl_read->rate_iops   = (read_iops > 0) ? (double)read_iops : 0.0;
    rl_read->rate_bytes  = (read_bw   > 0) ? (double)read_bw   : 0.0;
    rl_read->burst_iops  = rl_read->rate_iops;    // 1 second burst
    rl_read->burst_bytes = rl_read->rate_bytes;
    rl_read->tokens_iops = rl_read->burst_iops;   // start full , can change later based on token refill rate we choose
    rl_read->tokens_bytes= rl_read->burst_bytes;
    rl_read->last_refill = timeval_current();
    rl_read->queue_head = rl_read->queue_tail = NULL;
    rl_read->timer = NULL;
    // Initialize write limiter
    rl_write->rate_iops   = (write_iops > 0) ? (double)write_iops : 0.0;
    rl_write->rate_bytes  = (write_bw   > 0) ? (double)write_bw   : 0.0;
    rl_write->burst_iops  = rl_write->rate_iops;
    rl_write->burst_bytes = rl_write->rate_bytes;
    rl_write->tokens_iops = rl_write->burst_iops;
    rl_write->tokens_bytes= rl_write->burst_bytes;
    rl_write->last_refill = rl_read->last_refill; // use same current time
    rl_write->queue_head = rl_write->queue_tail = NULL;
    rl_write->timer = NULL;
}

static void refill_tokens(struct rate_limiter *rl, int snum)
{
    struct profile_stats *p = smbprofile_persvc_get(snum);
    if (p) {
        uint64_t total_ops_now = p->values.smb2_read_stats.count 
                            + p->values.smb2_write_stats.count;
        uint64_t bytes_out_now = p->values.smb2_read_stats.outbytes;  // bytes sent to clients
        uint64_t bytes_in_now  = p->values.smb2_write_stats.inbytes;  // bytes received from clients
        uint64_t total_bytes_now = bytes_out_now + bytes_in_now;
        
        uint64_t ops_delta = total_ops_now - rl->last_ops_count;
        uint64_t bytes_delta = total_bytes_now - rl->last_bytes_count;
        
        rl->tokens_iops -= (double) ops_delta;
        rl->tokens_bytes -= (double) bytes_delta;
        if (rl->tokens_iops < 0) rl->tokens_iops = 0;
        if (rl->tokens_bytes < 0) rl->tokens_bytes = 0;
    }

    struct timeval now;
    double elapsed;

    now = timeval_current();
    elapsed = timeval_elapsed(&rl->last_refill, &now);

    rl->tokens_iops += rl->rate_iops * elapsed;
    rl->tokens_bytes += rl->rate_bytes * elapsed;

    if (rl->tokens_iops > rl->burst_iops) {
        rl->tokens_iops = rl->burst_iops;
    }
    if (rl->tokens_bytes > rl->burst_bytes) {
        rl->tokens_bytes = rl->burst_bytes;
    }
    rl->last_refill = now;
}

static void rate_limit_timer_cb(struct tevent_context *ev, struct tevent_timer *te,
                                struct timeval t, void *private_data)
{
    struct rate_limiter *rl = talloc_get_type_abort(private_data, struct rate_limiter);
    struct tevent_req *req = rl->queue_head;

    refill_tokens(rl);

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
        struct timeval tv = timeval_current_ofs(0, 100); // 100ms retry interval
        rl->timer = tevent_add_timer(ev, rl, tv, rate_limit_timer_cb, rl);
    } else {
        rl->timer = NULL;
    }
}

static bool check_rate_limit(struct vfs_handle_struct *handle,
                             struct files_struct *fsp,
                             struct rate_limiter *rl,
                             size_t bytes,
                             struct tevent_req *req,
                             struct tevent_context *ev)
{
    int snum = SNUM(handle->conn);
    refill_tokens(rl, snum);
    if (rl->tokens_iops >= 1 && rl->tokens_bytes >= bytes) {
        rl->tokens_iops -= 1;
        rl->tokens_bytes -= bytes;
        return false; // no delay
    }

    struct rate_req_state *state = tevent_req_data(req, struct rate_req_state);
    state->handle = handle;
    state->fsp = fsp;
    state->bytes = bytes;
    state->limiter = rl;

    DLIST_ADD_END(rl->queue_head, req, struct tevent_req *);
    if (rl->queue_tail == NULL) rl->queue_tail = req;

    if (!rl->timer) {
        struct timeval tv = timeval_current_ofs(0, 100); // 100ms
        rl->timer = tevent_add_timer(ev, rl, tv, rate_limit_timer_cb, rl);
    }

    return true; // deferred
}
