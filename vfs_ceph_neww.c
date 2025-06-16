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
static bool vfs_ceph_load_config(struct vfs_handle_struct *handle,
				 struct vfs_ceph_config **config)
{
    struct vfs_ceph_config *config_tmp = NULL;
    int snum = SNUM(handle->conn);
    const char *module_name = "ceph_new";
    bool ok;

    if (SMB_VFS_HANDLE_TEST_DATA(handle)) {
        SMB_VFS_HANDLE_GET_DATA(handle, config_tmp,
                                struct vfs_ceph_config,
                                return false);
        goto done;
    }

    config_tmp = talloc_zero(handle->conn, struct vfs_ceph_config);
    if (config_tmp == NULL) {
        errno = ENOMEM;
        return false;
    }
    talloc_set_destructor(config_tmp, vfs_ceph_config_destructor);

    config_tmp->conf_file = lp_parm_const_string(snum, module_name,
                                                 "config_file", ".");
    config_tmp->user_id = lp_parm_const_string(snum, module_name,
                                               "user_id", "");
    config_tmp->fsname = lp_parm_const_string(snum, module_name,
                                             "filesystem", "");
    config_tmp->proxy = lp_parm_enum(snum, module_name, "proxy",
                                     enum_vfs_cephfs_proxy_vals,
                                     VFS_CEPHFS_PROXY_NO);
    if (config_tmp->proxy == -1) {
        DBG_ERR("[CEPH] value for proxy: mode unknown\n");
        return false;
    }

    // Read rate limit configuration
    bool rate_limit_enabled = lp_parm_bool(snum, module_name, "rate_limit", false);

    if (rate_limit_enabled) {
        uint32_t read_iops_limit = lp_parm_int(snum, module_name, "read_iops_limit", 0);
        uint32_t read_bw_limit   = lp_parm_int(snum, module_name, "read_bw_limit", 0);
        uint32_t write_iops_limit = lp_parm_int(snum, module_name, "write_iops_limit", 0);
        uint32_t write_bw_limit   = lp_parm_int(snum, module_name, "write_bw_limit", 0);

        init_rate_limiter(&config_tmp->rate_limiter[IO_OP_READ], (double)read_iops_limit, (double)read_bw_limit, true);
        init_rate_limiter(&config_tmp->rate_limiter[IO_OP_WRITE], (double)write_iops_limit, (double)write_bw_limit, true);
    }

    ok = vfs_cephfs_load_lib(config_tmp);
    if (!ok) {
        return false;
    }

    SMB_VFS_HANDLE_SET_DATA(handle, config_tmp, NULL,
                            struct vfs_ceph_config, return false);

done:
    *config = config_tmp;

    return true;
}