/*
   Unix SMB/CIFS implementation.
   Wrap disk only vfs functions to sidestep dodgy compilers.
   Copyright (C) Tim Potter 1998
   Copyright (C) Jeremy Allison 2007
   Copyright (C) Brian Chrisman 2011 <bchrisman@gmail.com>
   Copyright (C) Richard Sharpe 2011 <realrichardsharpe@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * This VFS only works with the libcephfs.so user-space client. It is not needed
 * if you are using the kernel client or the FUSE client.
 *
 * Add the following smb.conf parameter to each share that will be hosted on
 * Ceph:
 *
 *   vfs objects = [any others you need go here] ceph_new
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include <dirent.h>
#include <sys/statvfs.h>
#include "cephfs/libcephfs.h"
#include "smbprofile.h"
#include "modules/posixacl_xattr.h"
#include "lib/util/tevent_unix.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#ifndef LIBCEPHFS_VERSION
#define LIBCEPHFS_VERSION(maj, min, extra) ((maj << 16) + (min << 8) + extra)
#define LIBCEPHFS_VERSION_CODE LIBCEPHFS_VERSION(0, 0, 0)
#endif

........................................
.......................................................
// Existing code




// ##Rate Limting changes
static int vfs_ceph_connect(struct vfs_handle_struct *handle,
			    const char *service, const char *user)
{
	int ret = 0;
	struct cephmount_cached *entry = NULL;
	struct ceph_mount_info *mount = NULL;
	char *cookie;
	struct vfs_ceph_config *config = NULL;
	bool ok;

	ok = vfs_ceph_load_config(handle, &config);
	if (!ok) {
		return -1;
	}

	cookie = cephmount_get_cookie(handle, config);
	if (cookie == NULL) {
		return -1;
	}

	entry = cephmount_cache_update(cookie);
	if (entry != NULL) {
		goto connect_ok;
	}

	mount = cephmount_mount_fs(config);
	if (mount == NULL) {
		ret = -1;
		goto connect_fail;
	}

	ok = cephmount_cache_add(cookie, mount, &entry);
	if (!ok) {
		ret = -1;
		goto connect_fail;
	}

connect_ok:
	config->mount = entry->mount;
	config->mount_entry = entry;
	DBG_INFO("[CEPH] connection established with the server: "
		 "snum=%d cookie='%s'\n",
		 SNUM(handle->conn),
		 cookie);

    int snum = SNUM(handle->conn);
	uint32_t read_iops = lp_parm_uint(snum, "ceph_new", "read iops limit", 0);
	uint32_t read_bw   = lp_parm_uint(snum, "ceph_new", "read bw limit", 0);
	uint32_t write_iops = lp_parm_uint(snum, "ceph_new", "write iops limit", 0);
	uint32_t write_bw   = lp_parm_uint(snum, "ceph_new", "write bw limit", 0);
	smb_rate_limit_init_share(snum, read_iops, read_bw, write_iops, write_bw);

	/*
	 * Unless we have an async implementation of getxattrat turn this off.
	 */
	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");
connect_fail:
	talloc_free(cookie);
	return ret;
}



static ssize_t vfs_ceph_pread(struct vfs_handle_struct *handle,
			      files_struct *fsp,
			      void *data,
			      size_t n,
			      off_t offset)
{
	struct vfs_ceph_fh *cfh = NULL;
	ssize_t result;

	START_PROFILE_BYTES_X(SNUM(handle->conn), syscall_pread, n);
	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}

	result = vfs_ceph_ll_read(handle, cfh, offset, n, data);
out:
	DBG_DEBUG("[CEPH] pread: handle=%p name=%s n=%" PRIu64 "offset=%" PRIu64
		  " result=%" PRIu64 "\n",
		  handle,
		  fsp->fsp_name->base_name,
		  n,
		  (intmax_t)offset,
		  result);
	END_PROFILE_BYTES_X(syscall_pread);
	return lstatus_code(result);
}

struct vfs_ceph_aio_state {
	struct vfs_ceph_config *config;
	struct vfs_ceph_fh *cfh;
#if HAVE_CEPH_ASYNCIO
	struct tevent_req *req;
	bool orphaned;
	struct tevent_immediate *im;
	void *data;
	size_t len;
	off_t off;
	bool write;
	bool fsync;

	struct ceph_ll_io_info io_info;
	struct iovec iov;
#endif
	struct timespec start_time;
	struct timespec finish_time;
	ssize_t result;
	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes_x);
};

static void vfs_ceph_aio_start(struct vfs_ceph_aio_state *state)
{
	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);
	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes_x);
	PROFILE_TIMESTAMP(&state->start_time);
}

static void vfs_ceph_aio_finish(struct vfs_ceph_aio_state *state,
				ssize_t result)
{
	PROFILE_TIMESTAMP(&state->finish_time);
	state->vfs_aio_state.duration = nsec_time_diff(&state->finish_time,
						       &state->start_time);
	if (result < 0) {
		state->vfs_aio_state.error = (int)result;
	}

	state->result = result;
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes_x);
}

#if HAVE_CEPH_ASYNCIO

static void vfs_ceph_aio_done(struct tevent_context *ev,
			      struct tevent_immediate *im,
			      void *private_data);

static int vfs_ceph_require_tctx(struct vfs_ceph_aio_state *state,
				 struct tevent_context *ev)
{
	struct vfs_ceph_config *config = state->config;

	if (config->tctx != NULL) {
		return 0;
	}

	config->tctx = tevent_threaded_context_create(config, ev);
	if (config->tctx == NULL) {
		return -ENOMEM;
	}

	return 0;
}

static void vfs_ceph_aio_complete(struct ceph_ll_io_info *io_info)
{
	struct vfs_ceph_aio_state *state = io_info->priv;

	if (state->orphaned) {
		return;
	}

	DBG_DEBUG("[CEPH] aio_complete: ino=%" PRIu64
		  " fd=%d off=%jd len=%ju result=%jd\n",
		  state->cfh->iref.ino,
		  state->cfh->fd,
		  state->off,
		  state->len,
		  state->io_info.result);

	tevent_threaded_schedule_immediate(state->config->tctx,
					   state->im,
					   vfs_ceph_aio_done,
					   state->req);
}

static void vfs_ceph_aio_cleanup(struct tevent_req *req,
				 enum tevent_req_state req_state)
{
	struct vfs_ceph_aio_state *state = tevent_req_data(
		req, struct vfs_ceph_aio_state);

	if (req_state == TEVENT_REQ_IN_PROGRESS) {
		/*
		 * The job thread is still running, we need to protect the
		 * memory used by the job completion function.
		 */
		(void)talloc_reparent(req, NULL, state);
		state->orphaned = true;
	}
}

static void vfs_ceph_aio_submit(struct vfs_handle_struct *handle,
				struct tevent_req *req,
				struct tevent_context *ev)
{
	struct vfs_ceph_aio_state *state = tevent_req_data(
		req, struct vfs_ceph_aio_state);
	int64_t res;

	DBG_DEBUG("[CEPH] aio_send: ino=%" PRIu64 " fd=%d off=%jd len=%ju\n",
		  state->cfh->iref.ino,
		  state->cfh->fd,
		  state->off,
		  state->len);

	state->io_info.callback = vfs_ceph_aio_complete;
	state->iov.iov_base = state->data;
	state->iov.iov_len = state->len;
	state->io_info.priv = state;
	state->io_info.fh = state->cfh->fh;
	state->io_info.iov = &state->iov;
	state->io_info.iovcnt = 1;
	state->io_info.off = state->off;
	state->io_info.write = state->write;
	state->io_info.fsync = state->fsync;
	state->io_info.result = 0;

	vfs_ceph_aio_start(state);

	res = vfs_ceph_ll_nonblocking_readv_writev(handle,
						   state->cfh,
						   &state->io_info);
	if (res < 0) {
		state->result = (int)res;
		tevent_req_error(req, -((int)res));
		tevent_req_post(req, ev);
		return;
	}

	tevent_req_set_cleanup_fn(req, vfs_ceph_aio_cleanup);
	return;
}

static void vfs_ceph_aio_done(struct tevent_context *ev,
			      struct tevent_immediate *im,
			      void *private_data)
{
	struct tevent_req *req = private_data;
	struct vfs_ceph_aio_state *state = tevent_req_data(
		req, struct vfs_ceph_aio_state);

	DBG_DEBUG("[CEPH] aio_done: ino=%" PRIu64
		  " fd=%d off=%jd len=%ju result=%jd\n",
		  state->cfh->iref.ino,
		  state->cfh->fd,
		  state->off,
		  state->len,
		  state->io_info.result);

	vfs_ceph_aio_finish(state, state->io_info.result);
	if (state->result < 0) {
		tevent_req_error(req, -((int)state->result));
		return;
	}

	tevent_req_done(req);
}

static ssize_t vfs_ceph_aio_recv(struct tevent_req *req,
				 struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_ceph_aio_state *state = tevent_req_data(
		req, struct vfs_ceph_aio_state);
	ssize_t res = -1;

	DBG_DEBUG("[CEPH] aio_recv: ino=%" PRIu64
		  " fd=%d off=%jd len=%ju result=%ld\n",
		  state->cfh->iref.ino,
		  state->cfh->fd,
		  state->off,
		  state->len,
		  state->result);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		goto out;
	}

	*vfs_aio_state = state->vfs_aio_state;
	res = state->result;
out:
	tevent_req_received(req);
	return res;
}

#endif /* HAVE_CEPH_ASYNCIO */

static void vfs_ceph_aio_prepare(struct vfs_handle_struct *handle,
				 struct tevent_req *req,
				 struct tevent_context *ev,
				 struct files_struct *fsp)
{
	struct vfs_ceph_config *config = NULL;
	struct vfs_ceph_aio_state *state = NULL;
	int ret = -1;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_config,
				(void)0);
	if (config == NULL) {
		tevent_req_error(req, EINVAL);
		return;
	}

	state = tevent_req_data(req, struct vfs_ceph_aio_state);
	state->config = config;

#if HAVE_CEPH_ASYNCIO
	ret = vfs_ceph_require_tctx(state, ev);
	if (ret != 0) {
		tevent_req_error(req, -ret);
		return;
	}

	state->im = tevent_create_immediate(state);
	if (state->im == NULL) {
		tevent_req_error(req, ENOMEM);
		return;
	}
#endif

	ret = vfs_ceph_fetch_io_fh(handle, fsp, &state->cfh);
	if (ret != 0) {
		tevent_req_error(req, -ret);
	}
}

static struct tevent_req *vfs_ceph_pread_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      void *data,
					      size_t n,
					      off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_ceph_aio_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] pread_send: handle=%p name=%s data=%p n=%zu offset=%zd\n",
		  handle,
		  fsp->fsp_name->base_name,
		  data,
		  n,
		  offset);

	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_aio_state);
	if (req == NULL) {
		return NULL;
	}

	vfs_ceph_aio_prepare(handle, req, ev, fsp);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pread,
				     profile_p,
				     state->profile_bytes,
				     n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	SMBPROFILE_BYTES_ASYNC_START_X(syscall_asys_pread,
				       SNUM(handle->conn),
				       state->profile_bytes_x,
				       n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes_x);

#if HAVE_CEPH_ASYNCIO
	state->req = req;
	state->data = data;
	state->len = n;
	state->off = offset;

    // rate-limiting
	int snum = SNUM(handle->conn);
    struct rate_limiter *rl = &share_limiters[snum].read;
    if (rl->rate_iops != 0 || rl->rate_bytes != 0) {
        bool deferred = check_rate_limit(rl, handle, state, ev);
        if (deferred) {
            DBG_DEBUG("[CEPH] Read deferred: snum=%d tokens_iops=%.1f tokens_bytes=%.0f\n",
                      snum, rl->tokens_iops, rl->tokens_bytes);
            return req; // Not enough tokens; queued for later
        }
    }
	vfs_ceph_aio_submit(handle, req, ev);
	return req;
#endif
	vfs_ceph_aio_start(state);
	ret = vfs_ceph_ll_read(handle, state->cfh, offset, n, data);
	vfs_ceph_aio_finish(state, ret);
	if (ret < 0) {
		/* ceph returns -errno on error. */
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	/* Return and schedule the completion of the call. */
	return tevent_req_post(req, ev);
}

static ssize_t vfs_ceph_pwrite(struct vfs_handle_struct *handle,
			       files_struct *fsp,
			       const void *data,
			       size_t n,
			       off_t offset)
{
	struct vfs_ceph_fh *cfh = NULL;
	ssize_t result;

	START_PROFILE_BYTES_X(SNUM(handle->conn), syscall_pwrite, n);
	result = vfs_ceph_fetch_io_fh(handle, fsp, &cfh);
	if (result != 0) {
		goto out;
	}
	result = vfs_ceph_ll_write(handle, cfh, offset, n, data);
out:
	DBG_DEBUG("[CEPH] pwrite: name=%s data=%p n=%" PRIu64 "offset=%" PRIu64 "\n",
		  fsp->fsp_name->base_name,
		  data,
		  n,
		  (intmax_t)offset);
	END_PROFILE_BYTES_X(syscall_pwrite);
	return lstatus_code(result);
}

static struct tevent_req *vfs_ceph_pwrite_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct files_struct *fsp,
					       const void *data,
					       size_t n,
					       off_t offset)
{
	struct tevent_req *req = NULL;
	struct vfs_ceph_aio_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] pwrite_send: handle=%p name=%s data=%p n=%zu offset=%zd\n",
		  handle,
		  fsp->fsp_name->base_name,
		  data,
		  n,
		  offset);

	req = tevent_req_create(mem_ctx, &state, struct vfs_ceph_aio_state);
	if (req == NULL) {
		return NULL;
	}

	vfs_ceph_aio_prepare(handle, req, ev, fsp);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pwrite,
				     profile_p,
				     state->profile_bytes,
				     n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	SMBPROFILE_BYTES_ASYNC_START_X(syscall_asys_pwrite,
				       SNUM(handle->conn),
				       state->profile_bytes_x,
				       n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes_x);

#if HAVE_CEPH_ASYNCIO
	state->req = req;
	state->data = discard_const(data);
	state->len = n;
	state->off = offset;
	state->write = true;

    // rate-limiting
	int snum = SNUM(handle->conn);
    struct rate_limiter *rl = &share_limiters[snum].write;
    if (rl->rate_iops != 0 || rl->rate_bytes != 0) {
        bool deferred = check_rate_limit(rl, handle, state, ev);
        if (deferred) {
            DBG_DEBUG("[CEPH] Write deferred: snum=%d tokens_iops=%.1f tokens_bytes=%.0f\n",
                      snum, rl->tokens_iops, rl->tokens_bytes);
            return req;
        }
    }

	vfs_ceph_aio_submit(handle, req, ev);
	return req;
#endif

	vfs_ceph_aio_start(state);
	ret = vfs_ceph_ll_write(handle, state->cfh, offset, n, data);
	vfs_ceph_aio_finish(state, ret);
	if (ret < 0) {
		/* ceph returns -errno on error. */
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	/* Return and schedule the completion of the call. */
	return tevent_req_post(req, ev);
}



static struct vfs_fn_pointers ceph_new_fns = {
	/* Disk operations */

	.connect_fn = vfs_ceph_connect,
	.disconnect_fn = vfs_ceph_disconnect,
	.disk_free_fn = vfs_ceph_disk_free,
	.get_quota_fn = vfs_not_implemented_get_quota,
	.set_quota_fn = vfs_not_implemented_set_quota,
	.statvfs_fn = vfs_ceph_statvfs,
	.fs_capabilities_fn = vfs_ceph_fs_capabilities,

	/* Directory operations */

	.fdopendir_fn = vfs_ceph_fdopendir,
	.readdir_fn = vfs_ceph_readdir,
	.rewind_dir_fn = vfs_ceph_rewinddir,
	.mkdirat_fn = vfs_ceph_mkdirat,
	.closedir_fn = vfs_ceph_closedir,

	/* File operations */

	.create_dfs_pathat_fn = vfs_ceph_create_dfs_pathat,
	.read_dfs_pathat_fn = vfs_ceph_read_dfs_pathat,
	.openat_fn = vfs_ceph_openat,
	.close_fn = vfs_ceph_close,
	.pread_fn = vfs_ceph_pread,
	.pread_send_fn = vfs_ceph_pread_send,
	.pread_recv_fn = vfs_ceph_pread_recv,
	.pwrite_fn = vfs_ceph_pwrite,
	.pwrite_send_fn = vfs_ceph_pwrite_send,
	.pwrite_recv_fn = vfs_ceph_pwrite_recv,
	.lseek_fn = vfs_ceph_lseek,
	.sendfile_fn = vfs_ceph_sendfile,
	.recvfile_fn = vfs_ceph_recvfile,
	.renameat_fn = vfs_ceph_renameat,
	.fsync_send_fn = vfs_ceph_fsync_send,
	.fsync_recv_fn = vfs_ceph_fsync_recv,
	.stat_fn = vfs_ceph_stat,
	.fstat_fn = vfs_ceph_fstat,
	.lstat_fn = vfs_ceph_lstat,
	.fstatat_fn = vfs_ceph_fstatat,
	.unlinkat_fn = vfs_ceph_unlinkat,
	.fchmod_fn = vfs_ceph_fchmod,
	.fchown_fn = vfs_ceph_fchown,
	.lchown_fn = vfs_ceph_lchown,
	.chdir_fn = vfs_ceph_chdir,
	.getwd_fn = vfs_ceph_getwd,
	.fntimes_fn = vfs_ceph_fntimes,
	.ftruncate_fn = vfs_ceph_ftruncate,
	.fallocate_fn = vfs_ceph_fallocate,
	.lock_fn = vfs_ceph_lock,
	.filesystem_sharemode_fn = vfs_ceph_filesystem_sharemode,
	.fcntl_fn = vfs_ceph_fcntl,
	.linux_setlease_fn = vfs_not_implemented_linux_setlease,
	.getlock_fn = vfs_ceph_getlock,
	.symlinkat_fn = vfs_ceph_symlinkat,
	.readlinkat_fn = vfs_ceph_readlinkat,
	.linkat_fn = vfs_ceph_linkat,
	.mknodat_fn = vfs_ceph_mknodat,
	.realpath_fn = vfs_ceph_realpath,
	.fchflags_fn = vfs_not_implemented_fchflags,
	.get_real_filename_at_fn = vfs_ceph_get_real_filename_at,
	.connectpath_fn = vfs_ceph_connectpath,
	.fget_dos_attributes_fn = vfs_ceph_fget_dos_attributes,
	.fset_dos_attributes_fn = vfs_ceph_fset_dos_attributes,

	/* EA operations. */
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = vfs_ceph_fgetxattr,
	.flistxattr_fn = vfs_ceph_flistxattr,
	.fremovexattr_fn = vfs_ceph_fremovexattr,
	.fsetxattr_fn = vfs_ceph_fsetxattr,

	/* Posix ACL Operations */
	.sys_acl_get_fd_fn = posixacl_xattr_acl_get_fd,
	.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = posixacl_xattr_acl_set_fd,
	.sys_acl_delete_def_fd_fn = posixacl_xattr_acl_delete_def_fd,

	/* aio operations */
	.aio_force_fn = vfs_not_implemented_aio_force,
};

static_decl_vfs;
NTSTATUS vfs_ceph_new_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph_new", &ceph_new_fns);
}
