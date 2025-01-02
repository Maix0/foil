use std::ffi::{CStr, OsStr};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use ::libc;
use bitflags::Flags;
use libc::{fcntl, printf, uintmax_t, AT_FDCWD, MNT_DETACH, MS_MGC_VAL, S_IFDIR};
use privilged_op::{PrivilegedOp, PrivilegedOpError};

use crate::*;
use crate::{
    bind_mount::bind_mount,
    types::*,
    utils::{
        copy_file_data, create_file, create_pid_socketpair, die_unless_label_valid, ensure_dir,
        ensure_file, fdwalk, fork_intermediate_child, get_file_mode, get_newroot_path,
        label_create_file, label_exec, load_file_data, mkdir_with_parents, pivot_root, raw_clone,
        read_pid_from_socket, send_pid_on_socket, strappend, strappend_escape_for_mount_options,
        strconcat, strconcat3, write_file_at, write_to_fd, xcalloc, xclearenv, xsetenv, xunsetenv,
    },
};

use crate::privilged_op::privileged_op;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct NsInfo {
    pub name: *const libc::c_char,
    pub do_unshare: *mut bool,
    pub id: ino_t,
}

pub type SetupOpType = libc::c_uint;

pub const SETUP_CHMOD: SetupOpType = 18;
pub const SETUP_SET_HOSTNAME: SetupOpType = 17;
pub const SETUP_REMOUNT_RO_NO_RECURSIVE: SetupOpType = 16;
pub const SETUP_MAKE_SYMLINK: SetupOpType = 15;
pub const SETUP_MAKE_RO_BIND_FILE: SetupOpType = 14;
pub const SETUP_MAKE_BIND_FILE: SetupOpType = 13;
pub const SETUP_MAKE_FILE: SetupOpType = 12;
pub const SETUP_MAKE_DIR: SetupOpType = 11;
pub const SETUP_MOUNT_MQUEUE: SetupOpType = 10;
pub const SETUP_MOUNT_TMPFS: SetupOpType = 9;
pub const SETUP_MOUNT_DEV: SetupOpType = 8;
pub const SETUP_MOUNT_PROC: SetupOpType = 7;
pub const SETUP_OVERLAY_SRC: SetupOpType = 6;
pub const SETUP_RO_OVERLAY_MOUNT: SetupOpType = 5;
pub const SETUP_TMP_OVERLAY_MOUNT: SetupOpType = 4;
pub const SETUP_OVERLAY_MOUNT: SetupOpType = 3;
pub const SETUP_DEV_BIND_MOUNT: SetupOpType = 2;
pub const SETUP_RO_BIND_MOUNT: SetupOpType = 1;
pub const SETUP_BIND_MOUNT: SetupOpType = 0;

pub type SetupOpFlag = libc::c_uint;
pub const ALLOW_NOTEXIST: SetupOpFlag = 2;
pub const NO_CREATE_DEST: SetupOpFlag = 1;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _SetupOp {
    pub type_0: SetupOpType,
    pub source: *const libc::c_char,
    pub dest: *const libc::c_char,
    pub fd: libc::c_int,
    pub flags: SetupOpFlag,
    pub perms: libc::c_int,
    pub size: size_t,
    pub next: *mut SetupOp,
}

pub type SetupOp = _SetupOp;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _LockFile {
    pub path: *const libc::c_char,
    pub fd: libc::c_int,
    pub next: *mut LockFile,
}

pub type LockFile = _LockFile;

pub type PrivSepOpKind = libc::c_uint;
pub const PRIV_SEP_OP_SET_HOSTNAME: PrivSepOpKind = 8;
pub const PRIV_SEP_OP_REMOUNT_RO_NO_RECURSIVE: PrivSepOpKind = 7;
pub const PRIV_SEP_OP_MQUEUE_MOUNT: PrivSepOpKind = 6;
pub const PRIV_SEP_OP_DEVPTS_MOUNT: PrivSepOpKind = 5;
pub const PRIV_SEP_OP_TMPFS_MOUNT: PrivSepOpKind = 4;
pub const PRIV_SEP_OP_PROC_MOUNT: PrivSepOpKind = 3;
pub const PRIV_SEP_OP_OVERLAY_MOUNT: PrivSepOpKind = 2;
pub const PRIV_SEP_OP_BIND_MOUNT: PrivSepOpKind = 1;
pub const PRIV_SEP_OP_DONE: PrivSepOpKind = 0;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct PrivSepOp {
    pub op: u32,
    pub flags: bind_mount::BindOptions,
    pub perms: u32,
    pub size_arg: size_t,
    pub arg1_offset: u32,
    pub arg2_offset: u32,
}
#[derive(Copy, Clone)]
#[repr(C)]

pub struct _SeccompProgram {
    pub program: sock_fprog,
    pub next: *mut SeccompProgram,
}

pub type SeccompProgram = _SeccompProgram;

pub static mut real_uid: uid_t = 0;
pub static mut real_gid: gid_t = 0;
pub static mut overflow_uid: uid_t = 0;
pub static mut overflow_gid: gid_t = 0;
pub static mut is_privileged: bool = false;
pub static mut argv0: *const libc::c_char = 0 as *const libc::c_char;
pub static mut host_tty_dev: *const libc::c_char = 0 as *const libc::c_char;
pub static mut proc_fd: libc::c_int = -1;
pub static mut opt_exec_label: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_file_label: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_as_pid_1: bool = false;
pub static mut opt_argv0: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_chdir_path: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_assert_userns_disabled: bool = false;
pub static mut opt_disable_userns: bool = false;
pub static mut opt_unshare_user: bool = false;
pub static mut opt_unshare_user_try: bool = false;
pub static mut opt_unshare_pid: bool = false;
pub static mut opt_unshare_ipc: bool = false;
pub static mut opt_unshare_net: bool = false;
pub static mut opt_unshare_uts: bool = false;
pub static mut opt_unshare_cgroup: bool = false;
pub static mut opt_unshare_cgroup_try: bool = false;
pub static mut opt_needs_devpts: bool = false;
pub static mut opt_new_session: bool = false;
pub static mut opt_die_with_parent: bool = false;
pub static mut opt_sandbox_uid: uid_t = uid_t::MAX;
pub static mut opt_sandbox_gid: gid_t = gid_t::MAX;
pub static mut opt_sync_fd: libc::c_int = -1;
pub static mut opt_block_fd: libc::c_int = -1;
pub static mut opt_userns_block_fd: libc::c_int = -1;
pub static mut opt_info_fd: libc::c_int = -1;
pub static mut opt_json_status_fd: libc::c_int = -1;
pub static mut opt_seccomp_fd: libc::c_int = -1;
pub static mut opt_sandbox_hostname: *const libc::c_char =
    std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_args_data: *mut libc::c_char = std::ptr::null_mut() as *mut libc::c_char;
pub static mut opt_userns_fd: libc::c_int = -1;
pub static mut opt_userns2_fd: libc::c_int = -1;
pub static mut opt_pidns_fd: libc::c_int = -1;
pub static mut opt_tmp_overlay_count: libc::c_int = 0;
pub static mut next_perms: libc::c_int = -1;
pub static mut next_size_arg: size_t = 0;
pub static mut next_overlay_src_count: libc::c_int = 0;

static mut ns_infos: [NsInfo; 7] = unsafe {
    [
        {
            let init = NsInfo {
                name: c"cgroup".as_ptr(),
                do_unshare: &opt_unshare_cgroup as *const bool as *mut bool,
                id: 0,
            };
            init
        },
        {
            let init = NsInfo {
                name: c"ipc".as_ptr(),
                do_unshare: &opt_unshare_ipc as *const bool as *mut bool,
                id: 0,
            };
            init
        },
        {
            let init = NsInfo {
                name: c"mnt".as_ptr(),
                do_unshare: std::ptr::null_mut() as *mut bool,
                id: 0,
            };
            init
        },
        {
            let init = NsInfo {
                name: c"net".as_ptr(),
                do_unshare: &opt_unshare_net as *const bool as *mut bool,
                id: 0,
            };
            init
        },
        {
            let init = NsInfo {
                name: c"pid".as_ptr(),
                do_unshare: &opt_unshare_pid as *const bool as *mut bool,
                id: 0,
            };
            init
        },
        {
            let init = NsInfo {
                name: c"uts".as_ptr(),
                do_unshare: &opt_unshare_uts as *const bool as *mut bool,
                id: 0,
            };
            init
        },
        {
            let init = NsInfo {
                name: std::ptr::null_mut() as *const libc::c_char,
                do_unshare: std::ptr::null_mut() as *mut bool,
                id: 0,
            };
            init
        },
    ]
};

static mut ops: *mut SetupOp = std::ptr::null_mut() as *mut SetupOp;
#[inline]

unsafe fn _op_append_new() -> *mut SetupOp {
    let self_0 = xcalloc(1, ::core::mem::size_of::<SetupOp>()) as *mut SetupOp;
    if !last_op.is_null() {
        (*last_op).next = self_0;
    } else {
        ops = self_0;
    }
    last_op = self_0;
    return self_0;
}

static mut last_op: *mut SetupOp = std::ptr::null_mut() as *mut SetupOp;

unsafe fn setup_op_new(type_0: SetupOpType) -> *mut SetupOp {
    let op = _op_append_new();
    (*op).type_0 = type_0;
    (*op).fd = -1;
    (*op).flags = 0;
    return op;
}

static mut lock_files: *mut LockFile = std::ptr::null_mut() as *mut LockFile;

static mut last_lock_file: *mut LockFile = std::ptr::null_mut() as *mut LockFile;
#[inline]

unsafe fn _lock_file_append_new() -> *mut LockFile {
    let self_0 = xcalloc(1, ::core::mem::size_of::<LockFile>()) as *mut LockFile;
    if !last_lock_file.is_null() {
        (*last_lock_file).next = self_0;
    } else {
        lock_files = self_0;
    }
    last_lock_file = self_0;
    return self_0;
}

unsafe fn lock_file_new(path: *const libc::c_char) -> *mut LockFile {
    let lock = _lock_file_append_new();
    (*lock).path = path;
    return lock;
}
#[inline]

unsafe fn _seccomp_program_append_new() -> *mut SeccompProgram {
    let self_0 = xcalloc(1, ::core::mem::size_of::<SeccompProgram>()) as *mut SeccompProgram;
    if !last_seccomp_program.is_null() {
        (*last_seccomp_program).next = self_0;
    } else {
        seccomp_programs = self_0;
    }
    last_seccomp_program = self_0;
    return self_0;
}

static mut seccomp_programs: *mut SeccompProgram = std::ptr::null_mut() as *mut SeccompProgram;

static mut last_seccomp_program: *mut SeccompProgram = std::ptr::null_mut() as *mut SeccompProgram;

unsafe fn seccomp_program_new(fd: *mut libc::c_int) -> *mut SeccompProgram {
    let self_0 = _seccomp_program_append_new();
    let mut data = std::ptr::null_mut() as *mut libc::c_char;
    let mut len: size_t = 0;
    data = load_file_data(*fd, &mut len);
    if data.is_null() {
        die_with_error!(c"Can't read seccomp data".as_ptr());
    }
    close(*fd);
    *fd = -1;
    if len.wrapping_rem(8) != 0 {
        die!(c"Invalid seccomp data, must be multiple of 8".as_ptr());
    }
    (*self_0).program.len = len.wrapping_div(8) as _;
    (*self_0).program.filter = (if 0 != 0 {
        data as *mut libc::c_void
    } else {
        steal_pointer(&mut data as *mut *mut libc::c_char as *mut libc::c_void)
    }) as *mut sock_filter;
    return self_0;
}

unsafe fn seccomp_programs_apply() {
    let mut program = 0 as *mut SeccompProgram;
    program = seccomp_programs;
    while !program.is_null() {
        if prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &mut (*program).program as *mut sock_fprog,
        ) != 0
        {
            if errno!() == libc::EINVAL {
                die!(
                    c"Unable to set up system call filtering as requested: prctl(PR_SET_SECCOMP) reported EINVAL. (Hint: this requires a kernel configured with CONFIG_SECCOMP and CONFIG_SECCOMP_FILTER.)".as_ptr()
                        as *const u8 as *const libc::c_char,
                );
            }
            die_with_error!(c"prctl(PR_SET_SECCOMP)".as_ptr());
        }
        program = (*program).next;
    }
}

unsafe fn usage(ecode: libc::c_int, out: *mut FILE) {
    fprintf(
        out,
        c"usage: %s [OPTIONS...] [--] COMMAND [ARGS...]\n\n".as_ptr(),
        if !argv0.is_null() {
            argv0
        } else {
            c"bwrap".as_ptr()
        },
    );
    fprintf(
        out,
        c"    --help                       Print this help\n    --version                    Print version\n    --args FD                    Parse NUL-separated args from FD\n    --argv0 VALUE                Set argv[0] to the value VALUE before running the program\n    --level-prefix               Prepend e.g. <3> to diagnostic messages\n    --unshare-all                Unshare every namespace we support by default\n    --share-net                  Retain the network namespace (can only combine with --unshare-all)\n    --unshare-user               Create new user namespace (may be automatically implied if not setuid)\n    --unshare-user-try           Create new user namespace if possible else continue by skipping it\n    --unshare-ipc                Create new ipc namespace\n    --unshare-pid                Create new pid namespace\n    --unshare-net                Create new network namespace\n    --unshare-uts                Create new uts namespace\n    --unshare-cgroup             Create new cgroup namespace\n    --unshare-cgroup-try         Create new cgroup namespace if possible else continue by skipping it\n    --userns FD                  Use this user namespace (cannot combine with --unshare-user)\n    --userns2 FD                 After setup switch to this user namespace, only useful with --userns\n    --disable-userns             Disable further use of user namespaces inside sandbox\n    --assert-userns-disabled     Fail unless further use of user namespace inside sandbox is disabled\n    --pidns FD                   Use this pid namespace (as parent namespace if using --unshare-pid)\n    --uid UID                    Custom uid in the sandbox (requires --unshare-user or --userns)\n    --gid GID                    Custom gid in the sandbox (requires --unshare-user or --userns)\n    --hostname NAME              Custom hostname in the sandbox (requires --unshare-uts)\n    --chdir DIR                  Change directory to DIR\n    --clearenv                   Unset all environment variables\n    --setenv VAR VALUE           Set an environment variable\n    --unsetenv VAR               Unset an environment variable\n    --lock-file DEST             Take a lock on DEST while sandbox is running\n    --sync-fd FD                 Keep this fd open while sandbox is running\n    --bind SRC DEST              Bind mount the host path SRC on DEST\n    --bind-try SRC DEST          Equal to --bind but ignores non-existent SRC\n    --dev-bind SRC DEST          Bind mount the host path SRC on DEST, allowing device access\n    --dev-bind-try SRC DEST      Equal to --dev-bind but ignores non-existent SRC\n    --ro-bind SRC DEST           Bind mount the host path SRC readonly on DEST\n    --ro-bind-try SRC DEST       Equal to --ro-bind but ignores non-existent SRC\n    --bind-fd FD DEST            Bind open directory or path fd on DEST\n    --ro-bind-fd FD DEST         Bind open directory or path fd read-only on DEST\n    --remount-ro DEST            Remount DEST as readonly; does not recursively remount\n    --overlay-src SRC            Read files from SRC in the following overlay\n    --overlay RWSRC WORKDIR DEST Mount overlayfs on DEST, with RWSRC as the host path for writes and\n                                 WORKDIR an empty directory on the same filesystem as RWSRC\n    --tmp-overlay DEST           Mount overlayfs on DEST, with writes going to an invisible tmpfs\n    --ro-overlay DEST            Mount overlayfs read-only on DEST\n    --exec-label LABEL           Exec label for the sandbox\n    --file-label LABEL           File label for temporary sandbox content\n    --proc DEST                  Mount new procfs on DEST\n    --dev DEST                   Mount new dev on DEST\n    --tmpfs DEST                 Mount new tmpfs on DEST\n    --mqueue DEST                Mount new mqueue on DEST\n    --dir DEST                   Create dir at DEST\n    --file FD DEST               Copy from FD to destination DEST\n    --bind-data FD DEST          Copy from FD to file which is bind-mounted on DEST\n    --ro-bind-data FD DEST       Copy from FD to file which is readonly bind-mounted on DEST\n    --symlink SRC DEST           Create symlink at DEST with target SRC\n    --seccomp FD                 Load and use seccomp rules from FD (not repeatable)\n    --add-seccomp-fd FD          Load and use seccomp rules from FD (repeatable)\n    --block-fd FD                Block on FD until some data to read is available\n    --userns-block-fd FD         Block on FD until the user namespace is ready\n    --info-fd FD                 Write information about the running container to FD\n    --json-status-fd FD          Write container status to FD as multiple JSON documents\n    --new-session                Create a new terminal session\n    --die-with-parent            Kills with SIGKILL child process (COMMAND) when bwrap or bwrap's parent dies.\n    --as-pid-1                   Do not install a reaper process with PID=1\n    --cap-add CAP                Add cap CAP when running as privileged user\n    --cap-drop CAP               Drop cap CAP when running as privileged user\n    --perms OCTAL                Set permissions of next argument (--bind-data, --file, etc.)\n    --size BYTES                 Set size of next argument (only for --tmpfs)\n    --chmod OCTAL PATH           Change permissions of PATH (must already exist)\n".as_ptr()
            as *const u8 as *const libc::c_char,
    );
    exit(ecode);
}

unsafe fn handle_die_with_parent() {
    if opt_die_with_parent as libc::c_int != 0 && prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0 {
        die_with_error!(c"prctl".as_ptr());
    }
}

unsafe fn block_sigchild() {
    let mut mask = std::mem::zeroed();
    let mut status: libc::c_int = 0;
    sigemptyset(&mut mask);
    sigaddset(&mut mask, libc::SIGCHLD);
    if sigprocmask(
        libc::SIG_BLOCK,
        &mut mask,
        std::ptr::null_mut() as *mut sigset_t,
    ) == -1
    {
        die_with_error!(c"sigprocmask".as_ptr());
    }
    while waitpid(-1, &mut status, WNOHANG) > 0 {}
}

unsafe fn unblock_sigchild() {
    let mut mask = std::mem::zeroed();
    sigemptyset(&mut mask);
    sigaddset(&mut mask, libc::SIGCHLD);
    if sigprocmask(
        libc::SIG_UNBLOCK,
        &mut mask,
        std::ptr::null_mut() as *mut sigset_t,
    ) == -1
    {
        die_with_error!(c"sigprocmask".as_ptr());
    }
}

unsafe fn close_extra_fds(data: *mut libc::c_void, fd: libc::c_int) -> libc::c_int {
    let extra_fds = data as *mut libc::c_int;
    let mut i: libc::c_int = 0;
    i = 0;
    while *extra_fds.offset(i as isize) != -1 {
        if fd == *extra_fds.offset(i as isize) {
            return 0;
        }
        i += 1;
    }
    if fd <= 2 {
        return 0;
    }
    close(fd);
    return 0;
}

unsafe fn propagate_exit_status(status: libc::c_int) -> libc::c_int {
    if status & 0x7f as libc::c_int == 0 {
        return (status & 0xff00) >> 8;
    }
    if ((status & 0x7f as libc::c_int) + 1) as libc::c_schar as libc::c_int >> 1 > 0 {
        return 128 + (status & 0x7f as libc::c_int);
    }
    return 255;
}

unsafe fn dump_info(fd: libc::c_int, output: *const libc::c_char, exit_on_error: bool) {
    let len = strlen(output);
    if write_to_fd(fd, output, len as ssize_t) != 0 && exit_on_error {
        die_with_error!(c"Write to info_fd".as_ptr());
    }
}

unsafe fn report_child_exit_status(exitc: libc::c_int, setup_finished_fd: libc::c_int) {
    let mut s: ssize_t = 0;
    let mut data: [libc::c_char; 2] = [0; 2];
    let mut output = std::ptr::null_mut() as *mut libc::c_char;
    if opt_json_status_fd == -1 || setup_finished_fd == -1 {
        return;
    }
    s = loop {
        let __result = read(
            setup_finished_fd,
            data.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[libc::c_char; 2]>(),
        );
        if !(__result == -1 && errno!() == libc::EINTR) {
            break __result;
        }
    };
    if s == -1 && errno!() != libc::EAGAIN {
        die_with_error!(c"read eventfd".as_ptr());
    }
    if s != 1 {
        return;
    }
    output = xasprintf(c"{ \"exit-code\": %i }\n".as_ptr(), exitc);
    dump_info(opt_json_status_fd, output, false);
    close(opt_json_status_fd);
    opt_json_status_fd = -1;
    close(setup_finished_fd);
}

unsafe fn monitor_child(
    event_fd: libc::c_int,
    child_pid: pid_t,
    setup_finished_fd: libc::c_int,
) -> libc::c_int {
    let mut res: libc::c_int = 0;
    let mut val: u64 = 0;
    let mut s: ssize_t = 0;
    let mut signal_fd: libc::c_int = 0;
    let mut mask = std::mem::zeroed();
    let mut fds: [pollfd; 2] = [pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 2];
    let mut num_fds: libc::c_int = 0;
    let mut fdsi = std::mem::zeroed();
    let mut dont_close: [libc::c_int; 4] = [-1, -1, -1, -1];
    let mut j: libc::c_int = 0;
    let mut exitc: libc::c_int = 0;
    let mut died_pid: pid_t = 0;
    let mut died_status: libc::c_int = 0;
    if event_fd != -1 {
        let fresh0 = j;
        j = j.wrapping_add(1);
        dont_close[fresh0 as usize] = event_fd;
    }
    if opt_json_status_fd != -1 {
        let fresh1 = j;
        j = j.wrapping_add(1);
        dont_close[fresh1 as usize] = opt_json_status_fd;
    }
    if setup_finished_fd != -1 {
        let fresh2 = j;
        j = j.wrapping_add(1);
        dont_close[fresh2 as usize] = setup_finished_fd;
    }
    assert!(
        (j as libc::c_ulong)
            < (::core::mem::size_of::<[libc::c_int; 4]>() as libc::c_ulong)
                .wrapping_div(::core::mem::size_of::<libc::c_int>() as libc::c_ulong)
    );
    fdwalk(
        proc_fd,
        Some(close_extra_fds as unsafe fn(*mut libc::c_void, libc::c_int) -> libc::c_int),
        dont_close.as_mut_ptr() as *mut libc::c_void,
    );
    sigemptyset(&mut mask);
    sigaddset(&mut mask, libc::SIGCHLD);
    signal_fd = signalfd(-1, &mut mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
    if signal_fd == -1 {
        die_with_error!(c"Can't create signalfd".as_ptr());
    }
    num_fds = 1;
    fds[0].fd = signal_fd;
    fds[0].events = POLLIN as libc::c_short;
    if event_fd != -1 {
        fds[1].fd = event_fd;
        fds[1].events = POLLIN as libc::c_short;
        num_fds += 1;
    }
    loop {
        fds[1].revents = 0;
        fds[0].revents = fds[1].revents;
        res = poll(fds.as_mut_ptr(), num_fds as nfds_t, -1);
        if res == -1 && errno!() != libc::EINTR {
            die_with_error!(c"poll".as_ptr());
        }
        if event_fd != -1 {
            s = read(event_fd, &mut val as *mut u64 as *mut libc::c_void, 8);
            if s == -1 && errno!() != libc::EINTR && errno!() != libc::EAGAIN {
                die_with_error!(c"read eventfd".as_ptr());
            } else if s == 8 {
                exitc = (val - 1) as i32;
                report_child_exit_status(exitc, setup_finished_fd);
                return exitc;
            }
        }
        s = read(
            signal_fd,
            &mut fdsi as *mut signalfd_siginfo as *mut libc::c_void,
            ::core::mem::size_of::<signalfd_siginfo>(),
        );
        if s == -1 && errno!() != libc::EINTR && errno!() != libc::EAGAIN {
            die_with_error!(c"read signalfd".as_ptr());
        }
        loop {
            died_pid = waitpid(-1, &mut died_status, libc::WNOHANG);
            if !(died_pid > 0) {
                break;
            }
            if died_pid == child_pid {
                exitc = propagate_exit_status(died_status);
                report_child_exit_status(exitc, setup_finished_fd);
                return exitc;
            }
        }
    }
}

unsafe fn do_init(event_fd: libc::c_int, initial_pid: pid_t) -> libc::c_int {
    let mut initial_exit_status = 1;
    let mut lock = 0 as *mut LockFile;
    lock = lock_files;
    while !lock.is_null() {
        let fd = ({
            let mut __result: libc::c_long = 0;
            loop {
                __result = open((*lock).path, 0 | 0o2000000) as libc::c_long;
                if !(__result == -1 && errno!() == libc::EINTR) {
                    break;
                }
            }
            __result
        }) as libc::c_int;
        if fd == -1 {
            die_with_error!(c"Unable to open lock file %s".as_ptr(), (*lock).path,);
        }
        let mut l = {
            let init = flock {
                l_type: libc::F_RDLCK as libc::c_short,
                l_whence: libc::SEEK_SET as libc::c_short,
                l_start: 0,
                l_len: 0,
                l_pid: 0,
            };
            init
        };
        if ({
            let mut __result: libc::c_long = 0;
            loop {
                __result = fcntl(fd, 6, &mut l as *mut flock) as libc::c_long;
                if !(__result == -1 && errno!() == libc::EINTR) {
                    break;
                }
            }
            __result
        }) < 0
        {
            die_with_error!(c"Unable to lock file %s".as_ptr(), (*lock).path,);
        }
        (*lock).fd = fd;
        lock = (*lock).next;
    }
    handle_die_with_parent();
    seccomp_programs_apply();
    loop {
        let mut child: pid_t = 0;
        let mut status: libc::c_int = 0;
        child = ({
            let mut __result: libc::c_long = 0;
            loop {
                __result = wait(&mut status) as libc::c_long;
                if !(__result == -1 && errno!() == libc::EINTR) {
                    break;
                }
            }
            __result
        }) as pid_t;
        if child == initial_pid {
            initial_exit_status = propagate_exit_status(status);
            if event_fd != -1 {
                let mut val = (initial_exit_status + 1) as u64;
                let _res: isize = {
                    loop {
                        let __result = write(event_fd, &raw mut val as *const libc::c_void, 8);
                        if !(__result == -1 && errno!() == libc::EINTR) {
                            break __result as _;
                        }
                    }
                };
            }
        }
        if !(child == -1 && errno!() != libc::EINTR) {
            continue;
        }
        if errno!() != ECHILD {
            die_with_error!(c"init wait()".as_ptr());
        }
        break;
    }
    lock = lock_files;
    while !lock.is_null() {
        if (*lock).fd >= 0 {
            close((*lock).fd);
            (*lock).fd = -1;
        }
        lock = (*lock).next;
    }
    return initial_exit_status;
}

static mut opt_cap_add_or_drop_used: bool = false;

static mut requested_caps: [u32; 2] = [0, 0];

pub const REQUIRED_CAPS_0: libc::c_long = (1) << (21 & 31)
    | (1) << (18 & 31)
    | (1) << (12 & 31)
    | (1) << (7 & 31)
    | (1) << (6 & 31)
    | (1) << (19 & 31);

pub const REQUIRED_CAPS_1: libc::c_int = 0;

unsafe fn set_required_caps() {
    let mut hdr = {
        let init = __user_cap_header_struct {
            version: _LINUX_CAPABILITY_VERSION_3 as u32,
            pid: 0,
        };
        init
    };
    let mut data: [__user_cap_data_struct; 2] = [
        {
            let init = __user_cap_data_struct {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            };
            init
        },
        __user_cap_data_struct {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    data[0].effective = REQUIRED_CAPS_0 as u32;
    data[0].permitted = REQUIRED_CAPS_0 as u32;
    data[0].inheritable = 0;
    data[1].effective = REQUIRED_CAPS_1 as u32;
    data[1].permitted = REQUIRED_CAPS_1 as u32;
    data[1].inheritable = 0;
    if capset(&mut hdr, data.as_mut_ptr()) < 0 {
        die_with_error!(c"capset failed".as_ptr());
    }
}

unsafe fn drop_all_caps(keep_requested_caps: bool) {
    let mut hdr = {
        let init = __user_cap_header_struct {
            version: _LINUX_CAPABILITY_VERSION_3 as u32,
            pid: 0,
        };
        init
    };
    let mut data: [__user_cap_data_struct; 2] = [
        {
            let init = __user_cap_data_struct {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            };
            init
        },
        __user_cap_data_struct {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if keep_requested_caps {
        if !opt_cap_add_or_drop_used && real_uid == 0 {
            assert!(!is_privileged);
            return;
        }
        data[0].effective = requested_caps[0];
        data[0].permitted = requested_caps[0];
        data[0].inheritable = requested_caps[0];
        data[1].effective = requested_caps[1];
        data[1].permitted = requested_caps[1];
        data[1].inheritable = requested_caps[1];
    }
    if capset(&mut hdr, data.as_mut_ptr()) < 0 {
        if errno!() == EPERM && real_uid == 0 && !is_privileged {
            return;
        } else {
            die_with_error!(c"capset failed".as_ptr());
        }
    }
}

unsafe fn has_caps() -> bool {
    let mut hdr = {
        let init = __user_cap_header_struct {
            version: _LINUX_CAPABILITY_VERSION_3 as u32,
            pid: 0,
        };
        init
    };
    let mut data: [__user_cap_data_struct; 2] = [
        {
            let init = __user_cap_data_struct {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            };
            init
        },
        __user_cap_data_struct {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if capget(&mut hdr, data.as_mut_ptr()) < 0 {
        die_with_error!(c"capget failed".as_ptr());
    }
    return data[0].permitted != 0 || data[1].permitted != 0;
}

unsafe fn prctl_caps(caps: *mut u32, do_cap_bounding: bool, do_set_ambient: bool) {
    let mut cap: libc::c_ulong = 0;
    cap = 0;
    while cap <= CAP_LAST_CAP as libc::c_ulong {
        let mut keep = false;
        if cap < 32 {
            if (1) << (cap & 31) & *caps.offset(0) as libc::c_long != 0 {
                keep = true;
            }
        } else if (1) << (cap.wrapping_sub(32) & 31) & *caps.offset(1) as libc::c_long != 0 {
            keep = true;
        }
        if keep as libc::c_int != 0 && do_set_ambient as libc::c_int != 0 {
            let res = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0);
            if res == -1 && !(errno!() == libc::EINVAL || errno!() == libc::EPERM) {
                die_with_error!(c"Adding ambient capability %ld".as_ptr(), cap,);
            }
        }
        if !keep && do_cap_bounding as libc::c_int != 0 {
            let res_0 = prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
            if res_0 == -1 && !(errno!() == libc::EINVAL || errno!() == libc::EPERM) {
                die_with_error!(c"Dropping capability %ld from bounds".as_ptr(), cap,);
            }
        }
        cap = cap.wrapping_add(1);
    }
}

unsafe fn drop_cap_bounding_set(drop_all: bool) {
    if !drop_all {
        prctl_caps(requested_caps.as_mut_ptr(), true, false);
    } else {
        let mut no_caps: [u32; 2] = [0, 0];
        prctl_caps(no_caps.as_mut_ptr(), true, false);
    };
}

unsafe fn set_ambient_capabilities() {
    if is_privileged {
        return;
    }
    prctl_caps(requested_caps.as_mut_ptr(), false, true);
}

unsafe fn acquire_privs() {
    let mut euid: uid_t = 0;
    let mut new_fsuid: uid_t = 0;
    euid = geteuid();
    if real_uid != euid {
        if euid != 0 {
            die!(c"Unexpected setuid user %d, should be 0".as_ptr(), euid,);
        }
        is_privileged = true;
        if setfsuid(real_uid) < 0 {
            die_with_error!(c"Unable to set fsuid".as_ptr());
        }
        new_fsuid = setfsuid(uid_t::MAX) as uid_t;
        if new_fsuid != real_uid {
            die!(
                c"Unable to set fsuid (was %d)".as_ptr(),
                new_fsuid as libc::c_int,
            );
        }
        drop_cap_bounding_set(true);
        set_required_caps();
    } else if real_uid != 0 && has_caps() as libc::c_int != 0 {
        die!(
            c"Unexpected capabilities but not setuid, old file caps config?".as_ptr() as *const u8
                as *const libc::c_char,
        );
    } else if real_uid == 0 {
        let mut hdr = __user_cap_header_struct {
            version: _LINUX_CAPABILITY_VERSION_3 as u32,
            pid: 0,
        };
        let mut data: [__user_cap_data_struct; 2] = [
            __user_cap_data_struct {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            __user_cap_data_struct {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if capget(&mut hdr, data.as_mut_ptr()) < 0 {
            die_with_error!(c"capget (for uid == 0) failed".as_ptr());
        }
        requested_caps[0] = data[0].effective;
        requested_caps[1] = data[1].effective;
    }
}

unsafe fn switch_to_user_with_privs() {
    if opt_unshare_user as libc::c_int != 0 || opt_userns_fd != -1 {
        drop_cap_bounding_set(false);
    }
    if opt_userns_fd != -1 {
        if opt_sandbox_uid != real_uid && setuid(opt_sandbox_uid) < 0 {
            die_with_error!(c"unable to switch to uid %d".as_ptr(), opt_sandbox_uid,);
        }
        if opt_sandbox_gid != real_gid && setgid(opt_sandbox_gid) < 0 {
            die_with_error!(c"unable to switch to gid %d".as_ptr(), opt_sandbox_gid,);
        }
    }
    if !is_privileged {
        return;
    }
    if prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0 {
        die_with_error!(c"prctl(PR_SET_KEEPCAPS) failed".as_ptr());
    }
    if setuid(opt_sandbox_uid) < 0 {
        die_with_error!(c"unable to drop root uid".as_ptr());
    }
    set_required_caps();
}

unsafe fn drop_privs(keep_requested_caps: bool, already_changed_uid: bool) {
    assert!(!keep_requested_caps || !is_privileged);
    if is_privileged as libc::c_int != 0 && !already_changed_uid && setuid(opt_sandbox_uid) < 0 {
        die_with_error!(c"unable to drop root uid".as_ptr());
    }
    drop_all_caps(keep_requested_caps);
    if prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) != 0 {
        die_with_error!(c"can't set dumpable".as_ptr());
    }
}

unsafe fn write_uid_gid_map(
    sandbox_uid: uid_t,
    parent_uid: uid_t,
    sandbox_gid: uid_t,
    parent_gid: uid_t,
    pid: pid_t,
    deny_groups: bool,
    map_root: bool,
) {
    let mut uid_map = std::ptr::null_mut() as *mut libc::c_char;
    let mut gid_map = std::ptr::null_mut() as *mut libc::c_char;
    let mut dir = std::ptr::null_mut() as *mut libc::c_char;
    let mut dir_fd = -1;
    let mut old_fsuid = uid_t::MAX;
    if pid == -1 {
        dir = xstrdup(c"self".as_ptr());
    } else {
        dir = xasprintf(c"%d".as_ptr(), pid);
    }
    dir_fd = openat(proc_fd, dir, libc::O_PATH);
    if dir_fd < 0 {
        die_with_error!(c"open /proc/%s failed".as_ptr(), dir,);
    }
    if map_root as libc::c_int != 0 && parent_uid != 0 && sandbox_uid != 0 {
        uid_map = xasprintf(
            c"0 %d 1\n%d %d 1\n".as_ptr(),
            overflow_uid,
            sandbox_uid,
            parent_uid,
        );
    } else {
        uid_map = xasprintf(c"%d %d 1\n".as_ptr(), sandbox_uid, parent_uid);
    }
    if map_root as libc::c_int != 0 && parent_gid != 0 && sandbox_gid != 0 {
        gid_map = xasprintf(
            c"0 %d 1\n%d %d 1\n".as_ptr(),
            overflow_gid,
            sandbox_gid,
            parent_gid,
        );
    } else {
        gid_map = xasprintf(c"%d %d 1\n".as_ptr(), sandbox_gid, parent_gid);
    }
    if is_privileged {
        old_fsuid = setfsuid(0) as uid_t;
    }
    if write_file_at(dir_fd, c"uid_map".as_ptr(), uid_map) != 0 {
        die_with_error!(c"setting up uid map".as_ptr());
    }
    if deny_groups as libc::c_int != 0
        && write_file_at(dir_fd, c"setgroups".as_ptr(), c"deny\n".as_ptr()) != 0
    {
        if errno!() != ENOENT {
            die_with_error!(c"error writing to setgroups".as_ptr());
        }
    }
    if write_file_at(dir_fd, c"gid_map".as_ptr(), gid_map) != 0 {
        die_with_error!(c"setting up gid map".as_ptr());
    }
    if is_privileged {
        setfsuid(old_fsuid);
        if setfsuid(uid_t::MAX) as uid_t != real_uid {
            die!(c"Unable to re-set fsuid".as_ptr());
        }
    }
}

unsafe fn setup_newroot(unshare_pid: bool, privileged_op_socket: libc::c_int) {
    let mut op = 0 as *mut SetupOp;
    let mut tmp_overlay_idx = 0;
    let mut current_block_161: u64;
    op = ops;
    while !op.is_null() {
        let mut source = std::ptr::null_mut() as *mut libc::c_char;
        let mut dest = std::ptr::null_mut() as *mut libc::c_char;
        let mut source_mode = 0;
        let mut i: libc::c_uint = 0;
        if !((*op).source).is_null()
            && (*op).type_0 != SETUP_MAKE_SYMLINK as libc::c_int as libc::c_uint
        {
            source = get_oldroot_path((*op).source);
            source_mode = get_file_mode(source);
            if source_mode < 0 {
                if (*op).flags as libc::c_uint & ALLOW_NOTEXIST as libc::c_int as libc::c_uint != 0
                    && errno!() == ENOENT
                {
                    current_block_161 = 16668937799742929182;
                } else {
                    die_with_error!(c"Can't get type of source %s".as_ptr(), (*op).source,);
                }
            } else {
                current_block_161 = 3276175668257526147;
            }
        } else {
            current_block_161 = 3276175668257526147;
        }
        match current_block_161 {
            3276175668257526147 => {
                if !((*op).dest).is_null()
                    && (*op).flags as libc::c_uint & NO_CREATE_DEST as libc::c_int as libc::c_uint
                        == 0
                {
                    let mut parent_mode = 0o755;
                    if (*op).perms >= 0 && (*op).perms & 0o70 == 0 {
                        parent_mode &= !(0o50);
                    }
                    if (*op).perms >= 0 && (*op).perms & 0o7 == 0 {
                        parent_mode &= !(0o5);
                    }
                    dest = get_newroot_path((*op).dest);
                    if mkdir_with_parents(dest, parent_mode, false) != 0 {
                        die_with_error!(c"Can't mkdir parents for %s".as_ptr(), (*op).dest,);
                    }
                }
                static mut cover_proc_dirs: [*const libc::c_char; 4] = [
                    c"sys".as_ptr(),
                    c"sysrq-trigger".as_ptr(),
                    c"irq".as_ptr(),
                    c"bus".as_ptr(),
                ];
                static mut devnodes: [*const libc::c_char; 6] = [
                    c"null".as_ptr(),
                    c"zero".as_ptr(),
                    c"full".as_ptr(),
                    c"random".as_ptr(),
                    c"urandom".as_ptr(),
                    c"tty".as_ptr(),
                ];
                static mut stdionodes: [*const libc::c_char; 3] =
                    [c"stdin".as_ptr(), c"stdout".as_ptr(), c"stderr".as_ptr()];
                match (*op).type_0 {
                    1 | 2 | 0 => {
                        if source_mode == S_IFDIR as i32 {
                            if ensure_dir(dest, 0o755) != 0 {
                                die_with_error!(c"Can't mkdir %s".as_ptr(), (*op).dest,);
                            }
                        } else if ensure_file(dest, 0o444) != 0 {
                            die_with_error!(c"Can't create file at %s".as_ptr(), (*op).dest,);
                        }
                        privileged_op(
                            privileged_op_socket,
                            PrivilegedOp::BindMount {
                                src: OsString![source].into(),
                                dest: OsString![dest].into(),
                                flags: if (*op).type_0 == SETUP_RO_BIND_MOUNT {
                                    BindOptions::BIND_READONLY
                                } else {
                                    BindOptions::empty()
                                } | if (*op).type_0 == SETUP_DEV_BIND_MOUNT {
                                    BindOptions::BIND_DEVICES
                                } else {
                                    BindOptions::empty()
                                },
                            },
                        );
                        if (*op).fd >= 0 {
                            let mut fd_st = std::mem::zeroed();
                            let mut mount_st = std::mem::zeroed();
                            if fstat((*op).fd, &mut fd_st) != 0 {
                                die_with_error!(c"Can't stat fd %d".as_ptr(), (*op).fd,);
                            }
                            if lstat(dest, &mut mount_st) != 0 {
                                die_with_error!(c"Can't stat mount at %s".as_ptr(), dest,);
                            }
                            if fd_st.st_ino != mount_st.st_ino || fd_st.st_dev != mount_st.st_dev {
                                die_with_error!(c"Race condition binding dirfd".as_ptr()
                                    as *const u8
                                    as *const libc::c_char,);
                            }
                            close((*op).fd);
                            (*op).fd = -1;
                        }
                    }
                    3 | 5 | 4 => {
                        let mut sb = {
                            let init = StringBuilder {
                                buf: 0 as *mut libc::c_char,
                                size: 0,
                                offset: 0,
                            };
                            init
                        };
                        let mut multi_src = false;
                        if ensure_dir(dest, 0o755) != 0 {
                            die_with_error!(c"Can't mkdir %s".as_ptr(), (*op).dest,);
                        }
                        if !((*op).source).is_null() {
                            strappend(&mut sb, c"upperdir=/oldroot".as_ptr());
                            strappend_escape_for_mount_options(&mut sb, (*op).source);
                            strappend(&mut sb, c",workdir=/oldroot".as_ptr());
                            op = (*op).next;
                            strappend_escape_for_mount_options(&mut sb, (*op).source);
                            strappend(&mut sb, c",".as_ptr());
                        } else if (*op).type_0
                            == SETUP_TMP_OVERLAY_MOUNT as libc::c_int as libc::c_uint
                        {
                            let fresh3 = tmp_overlay_idx;
                            tmp_overlay_idx = tmp_overlay_idx + 1;
                            strappendf(
                                &mut sb as *mut StringBuilder,
                                c"upperdir=/tmp-overlay-upper-%1$d,workdir=/tmp-overlay-work-%1$d,"
                                    .as_ptr() as *const u8
                                    as *const libc::c_char,
                                fresh3,
                            );
                        }
                        strappend(&mut sb, c"lowerdir=/oldroot".as_ptr());
                        while !((*op).next).is_null()
                            && (*(*op).next).type_0
                                == SETUP_OVERLAY_SRC as libc::c_int as libc::c_uint
                        {
                            op = (*op).next;
                            if multi_src {
                                strappend(&mut sb, c":/oldroot".as_ptr());
                            }
                            strappend_escape_for_mount_options(&mut sb, (*op).source);
                            multi_src = true;
                        }
                        strappend(&mut sb, c",userxattr".as_ptr());
                        privileged_op(
                            privileged_op_socket,
                            PrivilegedOp::OverlayMount {
                                path: OsString![dest].into(),
                                options: OsString![sb.buf],
                            },
                        );
                        free(sb.buf as *mut libc::c_void);
                    }
                    16 => {
                        privileged_op(
                            privileged_op_socket,
                            PrivilegedOp::ReadOnlyRemount {
                                path: OsString![dest].into(),
                            },
                        );
                    }
                    7 => {
                        if ensure_dir(dest, 0o755) != 0 {
                            die_with_error!(c"Can't mkdir %s".as_ptr(), (*op).dest,);
                        }
                        if unshare_pid as libc::c_int != 0 || opt_pidns_fd != -1 {
                            privileged_op(
                                privileged_op_socket,
                                PrivilegedOp::ProcMount {
                                    path: OsString![dest].into(),
                                },
                            );
                        } else {
                            privileged_op(
                                privileged_op_socket,
                                PrivilegedOp::BindMount {
                                    src: OsString![c"oldroot/proc".as_ptr()].into(),
                                    dest: OsString![dest].into(),
                                    flags: BindOptions::empty(),
                                },
                            );
                        }
                        i = 0;
                        while (i as libc::c_ulong)
                            < (::core::mem::size_of::<[*const libc::c_char; 4]>() as libc::c_ulong)
                                .wrapping_div(
                                    ::core::mem::size_of::<*const libc::c_char>() as libc::c_ulong
                                )
                        {
                            let subdir =
                                strconcat3(dest, c"/".as_ptr(), cover_proc_dirs[i as usize]);
                            if access(subdir, W_OK) < 0 {
                                if !(errno!() == libc::EACCES
                                    || errno!() == libc::ENOENT
                                    || errno!() == libc::EROFS)
                                {
                                    die_with_error!(c"Can't access %s".as_ptr(), subdir,);
                                }
                            } else {
                                privileged_op(
                                    privileged_op_socket,
                                    PrivilegedOp::BindMount {
                                        src: OsString![subdir].into(),
                                        dest: OsString![subdir].into(),
                                        flags: BindOptions::BIND_READONLY,
                                    },
                                );
                            }
                            i = i.wrapping_add(1);
                        }
                    }
                    8 => {
                        if ensure_dir(dest, 0o755) != 0 {
                            die_with_error!(c"Can't mkdir %s".as_ptr(), (*op).dest,);
                        }
                        privileged_op(
                            privileged_op_socket,
                            PrivilegedOp::TmpfsMount {
                                size: None,
                                perms: 0o755,
                                path: OsString![dest].into(),
                            },
                        );
                        i = 0;
                        while (i as libc::c_ulong)
                            < (::core::mem::size_of::<[*const libc::c_char; 6]>() as libc::c_ulong)
                                .wrapping_div(
                                    ::core::mem::size_of::<*const libc::c_char>() as libc::c_ulong
                                )
                        {
                            let node_dest = strconcat3(dest, c"/".as_ptr(), devnodes[i as usize]);
                            let node_src =
                                strconcat(c"/oldroot/dev/".as_ptr(), devnodes[i as usize]);
                            if create_file(
                                node_dest,
                                0o444,
                                std::ptr::null_mut() as *const libc::c_char,
                            ) != 0
                            {
                                die_with_error!(
                                    c"Can't create file %s/%s".as_ptr() as *const u8
                                        as *const libc::c_char,
                                    (*op).dest,
                                    devnodes[i as usize],
                                );
                            }
                            privileged_op(
                                privileged_op_socket,
                                PrivilegedOp::BindMount {
                                    src: OsString![node_src].into(),
                                    dest: OsString![node_dest].into(),
                                    flags: BindOptions::BIND_DEVICES,
                                },
                            );
                            i = i.wrapping_add(1);
                        }
                        i = 0;
                        while (i as libc::c_ulong)
                            < (::core::mem::size_of::<[*const libc::c_char; 3]>() as libc::c_ulong)
                                .wrapping_div(
                                    ::core::mem::size_of::<*const libc::c_char>() as libc::c_ulong
                                )
                        {
                            let target = xasprintf(c"/proc/self/fd/%d".as_ptr(), i);
                            let node_dest_0 =
                                strconcat3(dest, c"/".as_ptr(), stdionodes[i as usize]);
                            if symlink(target, node_dest_0) < 0 {
                                die_with_error!(
                                    c"Can't create symlink %s/%s".as_ptr() as *const u8
                                        as *const libc::c_char,
                                    (*op).dest,
                                    stdionodes[i as usize],
                                );
                            }
                            i = i.wrapping_add(1);
                        }
                        let dev_fd = strconcat(dest, c"/fd".as_ptr());
                        if symlink(c"/proc/self/fd".as_ptr(), dev_fd) < 0 {
                            die_with_error!(c"Can't create symlink %s".as_ptr(), dev_fd,);
                        }
                        let dev_core = strconcat(dest, c"/core".as_ptr());
                        if symlink(c"/proc/kcore".as_ptr(), dev_core) < 0 {
                            die_with_error!(c"Can't create symlink %s".as_ptr(), dev_core,);
                        }
                        let pts = strconcat(dest, c"/pts".as_ptr());
                        let ptmx = strconcat(dest, c"/ptmx".as_ptr());
                        let shm = strconcat(dest, c"/shm".as_ptr());
                        if mkdir(shm, 0o755) == -1 {
                            die_with_error!(c"Can't create %s/shm".as_ptr(), (*op).dest,);
                        }
                        if mkdir(pts, 0o755) == -1 {
                            die_with_error!(c"Can't create %s/devpts".as_ptr(), (*op).dest,);
                        }
                        privileged_op(
                            privileged_op_socket,
                            PrivilegedOp::DevMount {
                                path: OsString![pts].into(),
                            },
                        );
                        if symlink(c"pts/ptmx".as_ptr(), ptmx) != 0 {
                            die_with_error!(
                                c"Can't make symlink at %s/ptmx".as_ptr() as *const u8
                                    as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        if !host_tty_dev.is_null() && *host_tty_dev as libc::c_int != 0 {
                            let src_tty_dev = strconcat(c"/oldroot".as_ptr(), host_tty_dev);
                            let dest_console = strconcat(dest, c"/console".as_ptr());
                            if create_file(
                                dest_console,
                                0o444,
                                std::ptr::null_mut() as *const libc::c_char,
                            ) != 0
                            {
                                die_with_error!(c"creating %s/console".as_ptr(), (*op).dest,);
                            }
                            privileged_op(
                                privileged_op_socket,
                                PrivilegedOp::BindMount {
                                    src: OsString![src_tty_dev].into(),
                                    dest: OsString![dest_console].into(),
                                    flags: BindOptions::BIND_DEVICES,
                                },
                            );
                        }
                    }
                    9 => {
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0);
                        assert!((*op).perms <= 0o7777);
                        if ensure_dir(dest, 0o755) != 0 {
                            die_with_error!(c"Can't mkdir %s".as_ptr(), (*op).dest,);
                        }
                        privileged_op(
                            privileged_op_socket,
                            PrivilegedOp::TmpfsMount {
                                size: NonZeroUsize::new((*op).size),
                                perms: ((*op).perms) as _,
                                path: OsString![dest].into(),
                            },
                        );
                    }
                    10 => {
                        if ensure_dir(dest, 0o755) != 0 {
                            die_with_error!(c"Can't mkdir %s".as_ptr(), (*op).dest,);
                        }
                        privileged_op(
                            privileged_op_socket,
                            PrivilegedOp::MqueueMount {
                                path: OsString![dest].into(),
                            },
                        );
                    }
                    11 => {
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0);
                        assert!((*op).perms <= 0o7777);
                        if ensure_dir(dest, (*op).perms as mode_t) != 0 {
                            die_with_error!(c"Can't mkdir %s".as_ptr(), (*op).dest,);
                        }
                    }
                    18 => {
                        assert!(!((*op).dest).is_null());
                        assert!(dest.is_null());
                        dest = get_newroot_path((*op).dest);
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0);
                        assert!((*op).perms <= 0o7777);
                        if chmod(dest, (*op).perms as mode_t) != 0 {
                            die_with_error!(
                                c"Can't chmod %#o %s".as_ptr(),
                                (*op).perms,
                                (*op).dest,
                            );
                        }
                    }
                    12 => {
                        let mut dest_fd = -1;
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0);
                        assert!((*op).perms <= 0o7777);
                        dest_fd = creat(dest, (*op).perms as mode_t);
                        if dest_fd == -1 {
                            die_with_error!(c"Can't create file %s".as_ptr(), (*op).dest,);
                        }
                        if copy_file_data((*op).fd, dest_fd) != 0 {
                            die_with_error!(
                                c"Can't write data to file %s".as_ptr() as *const u8
                                    as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        close((*op).fd);
                        (*op).fd = -1;
                    }
                    13 | 14 => {
                        let mut dest_fd_0 = -1;
                        let mut tempfile: [libc::c_char; 16] =
                            *::core::mem::transmute::<&[u8; 16], &mut [libc::c_char; 16]>(
                                b"/bindfileXXXXXX\0",
                            );
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0);
                        assert!((*op).perms <= 0o7777);
                        dest_fd_0 = mkstemp(tempfile.as_mut_ptr());
                        if dest_fd_0 == -1 {
                            die_with_error!(
                                c"Can't create tmpfile for %s".as_ptr() as *const u8
                                    as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        if fchmod(dest_fd_0, (*op).perms as mode_t) != 0 {
                            die_with_error!(
                                c"Can't set mode %#o on file to be used for %s".as_ptr()
                                    as *const u8
                                    as *const libc::c_char,
                                (*op).perms,
                                (*op).dest,
                            );
                        }
                        if copy_file_data((*op).fd, dest_fd_0) != 0 {
                            die_with_error!(
                                c"Can't write data to file %s".as_ptr() as *const u8
                                    as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        close((*op).fd);
                        (*op).fd = -1;
                        assert!(!dest.is_null());
                        if ensure_file(dest, 0o444) != 0 {
                            die_with_error!(c"Can't create file at %s".as_ptr(), (*op).dest,);
                        }
                        privileged_op(
                            privileged_op_socket,
                            privilged_op::PrivilegedOp::BindMount {
                                src: OsString![tempfile.as_mut_ptr()].into(),
                                dest: OsString![dest].into(),
                                flags: (if (*op).type_0
                                    == SETUP_MAKE_RO_BIND_FILE as libc::c_int as libc::c_uint
                                {
                                    BindOptions::BIND_READONLY
                                } else {
                                    BindOptions::empty()
                                }),
                            },
                        );
                        unlink(tempfile.as_mut_ptr());
                    }
                    15 => {
                        assert!(!((*op).source).is_null());
                        if symlink((*op).source, dest) != 0 {
                            if errno!() == libc::EEXIST {
                                let existing = readlink_malloc(dest);
                                if existing.is_null() {
                                    if errno!() == libc::EINVAL {
                                        die!(
                                            c"Can't make symlink at %s: destination exists and is not a symlink".as_ptr()
                                                as *const u8 as *const libc::c_char,
                                            (*op).dest,
                                        );
                                    } else {
                                        die_with_error!(
                                            c"Can't make symlink at %s: destination exists, and cannot read symlink target".as_ptr()
                                                as *const u8 as *const libc::c_char,
                                            (*op).dest,
                                        );
                                    }
                                }
                                if !(strcmp(existing, (*op).source) == 0) {
                                    die!(
                                        c"Can't make symlink at %s: existing destination is %s"
                                            .as_ptr()
                                            as *const u8
                                            as *const libc::c_char,
                                        (*op).dest,
                                        existing,
                                    );
                                }
                            } else {
                                die_with_error!(
                                    c"Can't make symlink at %s".as_ptr() as *const u8
                                        as *const libc::c_char,
                                    (*op).dest,
                                );
                            }
                        }
                    }
                    17 => {
                        assert!(!((*op).dest).is_null());
                        privileged_op(
                            privileged_op_socket,
                            privilged_op::PrivilegedOp::SetHostname {
                                name: OsString![(*op).dest],
                            },
                        );
                    }
                    6 | _ => {
                        die!(c"Unexpected type %d".as_ptr(), (*op).type_0,);
                    }
                }
            }
            _ => {}
        }
        op = (*op).next;
    }
    privileged_op(privileged_op_socket, privilged_op::PrivilegedOp::Done);
}

unsafe fn close_ops_fd() {
    let mut op = 0 as *mut SetupOp;
    op = ops;
    while !op.is_null() {
        if (*op).fd != -1 {
            close((*op).fd);
            (*op).fd = -1;
        }
        op = (*op).next;
    }
}

unsafe fn resolve_symlinks_in_ops() {
    let mut op = 0 as *mut SetupOp;
    op = ops;
    while !op.is_null() {
        let mut old_source = 0 as *const libc::c_char;
        match (*op).type_0 {
            1 | 2 | 0 | 6 | 3 => {
                old_source = (*op).source;
                (*op).source = realpath(old_source, std::ptr::null_mut() as *mut libc::c_char);
                if ((*op).source).is_null() {
                    if (*op).flags as libc::c_uint & ALLOW_NOTEXIST as libc::c_int as libc::c_uint
                        != 0
                        && errno!() == ENOENT
                    {
                        (*op).source = old_source;
                    } else {
                        die_with_error!(c"Can't find source path %s".as_ptr(), old_source,);
                    }
                }
            }
            5 | 4 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | _ => {}
        }
        op = (*op).next;
    }
}

unsafe fn print_version_and_exit() -> ! {
    printf(c"%s\n".as_ptr(), PACKAGE_STRING.as_ptr());
    exit(0);
}

unsafe fn is_modifier_option(option: *const libc::c_char) -> libc::c_int {
    return (strcmp(option, c"--perms".as_ptr()) == 0 || strcmp(option, c"--size".as_ptr()) == 0)
        as libc::c_int;
}

unsafe fn warn_only_last_option(mut _name: *const libc::c_char) {
    bwrap_log!(
        LOG_WARNING,
        c"Only the last %s option will take effect".as_ptr(),
        name,
    );
}

unsafe fn make_setup_overlay_src_ops(argv: *const *const libc::c_char) {
    let mut i: libc::c_int = 0;
    let mut op = 0 as *mut SetupOp;
    i = 1;
    while i <= next_overlay_src_count {
        op = setup_op_new(SETUP_OVERLAY_SRC);
        (*op).source = *argv.offset((1 - 2 * i) as isize);
        i += 1;
    }
    next_overlay_src_count = 0;
}

unsafe fn parse_args_recurse(
    argcp: *mut libc::c_int,
    argvp: *mut *mut *const libc::c_char,
    in_file: bool,
    total_parsed_argc_p: *mut libc::c_int,
) {
    let mut op = 0 as *mut SetupOp;
    let mut argc = *argcp;
    let mut argv = *argvp;
    static mut MAX_ARGS: i32 = 9000;
    if *total_parsed_argc_p > MAX_ARGS {
        die!(
            c"Exceeded maximum number of arguments %u".as_ptr(),
            MAX_ARGS,
        );
    }
    while argc > 0 {
        let arg = *argv.offset(0);
        if strcmp(arg, c"--help".as_ptr()) == 0 {
            usage(EXIT_SUCCESS, stdout);
        } else if strcmp(arg, c"--version".as_ptr()) == 0 {
            print_version_and_exit();
        } else if strcmp(arg, c"--args".as_ptr()) == 0 {
            let mut the_fd: libc::c_int = 0;
            let mut endptr = 0 as *mut libc::c_char;
            let mut p = 0 as *const libc::c_char;
            let mut data_end = 0 as *const libc::c_char;
            let mut data_len: size_t = 0;
            let mut data_argv = std::ptr::null_mut() as *mut *const libc::c_char;
            let mut data_argv_copy = 0 as *mut *const libc::c_char;
            let mut data_argc: libc::c_int = 0;
            let mut i: libc::c_int = 0;
            if in_file {
                die!(c"--args not supported in arguments file".as_ptr());
            }
            if argc < 2 {
                die!(c"--args takes an argument".as_ptr());
            }
            the_fd = strtol(*argv.offset(1), &mut endptr, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr.offset(0) as libc::c_int != 0
                || the_fd < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_args_data = load_file_data(the_fd, &mut data_len);
            if opt_args_data.is_null() {
                die_with_error!(c"Can't read --args data".as_ptr());
            }
            close(the_fd);
            data_end = opt_args_data.offset(data_len as isize);
            data_argc = 0;
            p = opt_args_data;
            while !p.is_null() && p < data_end {
                data_argc += 1;
                *total_parsed_argc_p += 1;
                if *total_parsed_argc_p > MAX_ARGS {
                    die!(
                        c"Exceeded maximum number of arguments %u".as_ptr() as *const u8
                            as *const libc::c_char,
                        MAX_ARGS,
                    );
                }
                p = memchr(
                    p as *const libc::c_void,
                    0,
                    (data_end).offset_from(p) as usize,
                ) as *const libc::c_char;
                if !p.is_null() {
                    p = p.offset(1);
                }
            }
            data_argv = xcalloc(
                (data_argc + 1) as size_t,
                ::core::mem::size_of::<*mut libc::c_char>(),
            ) as *mut *const libc::c_char;
            i = 0;
            p = opt_args_data;
            while !p.is_null() && p < data_end {
                let fresh4 = i;
                i = i + 1;
                let ref mut fresh5 = *data_argv.offset(fresh4 as _);
                *fresh5 = p;
                p = memchr(
                    p as *const libc::c_void,
                    0,
                    data_end.offset_from(p) as usize,
                ) as *const libc::c_char;
                if !p.is_null() {
                    p = p.offset(1);
                }
            }
            data_argv_copy = data_argv;
            parse_args_recurse(
                &mut data_argc,
                &mut data_argv_copy,
                true,
                total_parsed_argc_p,
            );
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--argv0".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--argv0 takes one argument".as_ptr());
            }
            if !opt_argv0.is_null() {
                die!(c"--argv0 used multiple times".as_ptr());
            }
            opt_argv0 = *argv.offset(1);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--level-prefix".as_ptr()) == 0 {
            bwrap_level_prefix = true;
        } else if strcmp(arg, c"--unshare-all".as_ptr()) == 0 {
            opt_unshare_net = true;
            opt_unshare_cgroup_try = opt_unshare_net;
            opt_unshare_uts = opt_unshare_cgroup_try;
            opt_unshare_pid = opt_unshare_uts;
            opt_unshare_ipc = opt_unshare_pid;
            opt_unshare_user_try = opt_unshare_ipc;
        } else if strcmp(arg, c"--unshare-user".as_ptr()) == 0 {
            opt_unshare_user = true;
        } else if strcmp(arg, c"--unshare-user-try".as_ptr()) == 0 {
            opt_unshare_user_try = true;
        } else if strcmp(arg, c"--unshare-ipc".as_ptr()) == 0 {
            opt_unshare_ipc = true;
        } else if strcmp(arg, c"--unshare-pid".as_ptr()) == 0 {
            opt_unshare_pid = true;
        } else if strcmp(arg, c"--unshare-net".as_ptr()) == 0 {
            opt_unshare_net = true;
        } else if strcmp(arg, c"--unshare-uts".as_ptr()) == 0 {
            opt_unshare_uts = true;
        } else if strcmp(arg, c"--unshare-cgroup".as_ptr()) == 0 {
            opt_unshare_cgroup = true;
        } else if strcmp(arg, c"--unshare-cgroup-try".as_ptr()) == 0 {
            opt_unshare_cgroup_try = true;
        } else if strcmp(arg, c"--share-net".as_ptr()) == 0 {
            opt_unshare_net = false;
        } else if strcmp(arg, c"--chdir".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--chdir takes one argument".as_ptr());
            }
            if !opt_chdir_path.is_null() {
                warn_only_last_option(c"--chdir".as_ptr());
            }
            opt_chdir_path = *argv.offset(1);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--disable-userns".as_ptr()) == 0 {
            opt_disable_userns = true;
        } else if strcmp(arg, c"--assert-userns-disabled".as_ptr()) == 0 {
            opt_assert_userns_disabled = true;
        } else if strcmp(arg, c"--remount-ro".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--remount-ro takes one argument".as_ptr());
            }
            op = setup_op_new(SETUP_REMOUNT_RO_NO_RECURSIVE);
            (*op).dest = *argv.offset(1);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--bind".as_ptr()) == 0 || strcmp(arg, c"--bind-try".as_ptr()) == 0 {
            if argc < 3 {
                die!(c"%s takes two arguments".as_ptr(), arg,);
            }
            op = setup_op_new(SETUP_BIND_MOUNT);
            (*op).source = *argv.offset(1);
            (*op).dest = *argv.offset(2);
            if strcmp(arg, c"--bind-try".as_ptr()) == 0 {
                (*op).flags = ALLOW_NOTEXIST;
            }
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--ro-bind".as_ptr()) == 0
            || strcmp(arg, c"--ro-bind-try".as_ptr()) == 0
        {
            if argc < 3 {
                die!(c"%s takes two arguments".as_ptr(), arg,);
            }
            op = setup_op_new(SETUP_RO_BIND_MOUNT);
            (*op).source = *argv.offset(1);
            (*op).dest = *argv.offset(2);
            if strcmp(arg, c"--ro-bind-try".as_ptr()) == 0 {
                (*op).flags = ALLOW_NOTEXIST;
            }
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--dev-bind".as_ptr()) == 0
            || strcmp(arg, c"--dev-bind-try".as_ptr()) == 0
        {
            if argc < 3 {
                die!(c"%s takes two arguments".as_ptr(), arg,);
            }
            op = setup_op_new(SETUP_DEV_BIND_MOUNT);
            (*op).source = *argv.offset(1);
            (*op).dest = *argv.offset(2);
            if strcmp(arg, c"--dev-bind-try".as_ptr()) == 0 {
                (*op).flags = ALLOW_NOTEXIST;
            }
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--bind-fd".as_ptr()) == 0
            || strcmp(arg, c"--ro-bind-fd".as_ptr()) == 0
        {
            let mut src_fd: libc::c_int = 0;
            let mut endptr_0 = 0 as *mut libc::c_char;
            if argc < 3 {
                die!(c"--bind-fd takes two arguments".as_ptr());
            }
            src_fd = strtol(*argv.offset(1), &mut endptr_0, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_0.offset(0) as libc::c_int != 0
                || src_fd < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            if strcmp(arg, c"--ro-bind-fd".as_ptr()) == 0 {
                op = setup_op_new(SETUP_RO_BIND_MOUNT);
            } else {
                op = setup_op_new(SETUP_BIND_MOUNT);
            }
            (*op).source = xasprintf(c"/proc/self/fd/%d".as_ptr(), src_fd);
            (*op).fd = src_fd;
            (*op).dest = *argv.offset(2);
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--overlay-src".as_ptr()) == 0 {
            if is_privileged {
                die!(
                    c"The --overlay-src option is not permitted in setuid mode".as_ptr()
                        as *const u8 as *const libc::c_char,
                );
            }
            next_overlay_src_count += 1;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--overlay".as_ptr()) == 0 {
            let mut workdir_op = 0 as *mut SetupOp;
            if is_privileged {
                die!(
                    c"The --overlay option is not permitted in setuid mode".as_ptr() as *const u8
                        as *const libc::c_char,
                );
            }
            if argc < 4 {
                die!(c"--overlay takes three arguments".as_ptr());
            }
            if next_overlay_src_count < 1 {
                die!(
                    c"--overlay requires at least one --overlay-src".as_ptr() as *const u8
                        as *const libc::c_char,
                );
            }
            op = setup_op_new(SETUP_OVERLAY_MOUNT);
            (*op).source = *argv.offset(1);
            workdir_op = setup_op_new(SETUP_OVERLAY_SRC);
            (*workdir_op).source = *argv.offset(2);
            (*op).dest = *argv.offset(3);
            make_setup_overlay_src_ops(argv);
            argv = argv.offset(3);
            argc -= 3;
        } else if strcmp(arg, c"--tmp-overlay".as_ptr()) == 0 {
            if is_privileged {
                die!(
                    c"The --tmp-overlay option is not permitted in setuid mode".as_ptr()
                        as *const u8 as *const libc::c_char,
                );
            }
            if argc < 2 {
                die!(c"--tmp-overlay takes an argument".as_ptr());
            }
            if next_overlay_src_count < 1 {
                die!(
                    c"--tmp-overlay requires at least one --overlay-src".as_ptr() as *const u8
                        as *const libc::c_char,
                );
            }
            op = setup_op_new(SETUP_TMP_OVERLAY_MOUNT);
            (*op).dest = *argv.offset(1);
            make_setup_overlay_src_ops(argv);
            opt_tmp_overlay_count += 1;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--ro-overlay".as_ptr()) == 0 {
            if is_privileged {
                die!(
                    c"The --ro-overlay option is not permitted in setuid mode".as_ptr() as *const u8
                        as *const libc::c_char,
                );
            }
            if argc < 2 {
                die!(c"--ro-overlay takes an argument".as_ptr());
            }
            if next_overlay_src_count < 2 {
                die!(
                    c"--ro-overlay requires at least two --overlay-src".as_ptr() as *const u8
                        as *const libc::c_char,
                );
            }
            op = setup_op_new(SETUP_RO_OVERLAY_MOUNT);
            (*op).dest = *argv.offset(1);
            make_setup_overlay_src_ops(argv);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--proc".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--proc takes an argument".as_ptr());
            }
            op = setup_op_new(SETUP_MOUNT_PROC);
            (*op).dest = *argv.offset(1);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--exec-label".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--exec-label takes an argument".as_ptr());
            }
            if !opt_exec_label.is_null() {
                warn_only_last_option(c"--exec-label".as_ptr());
            }
            opt_exec_label = *argv.offset(1);
            die_unless_label_valid(opt_exec_label);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--file-label".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--file-label takes an argument".as_ptr());
            }
            if !opt_file_label.is_null() {
                warn_only_last_option(c"--file-label".as_ptr());
            }
            opt_file_label = *argv.offset(1);
            die_unless_label_valid(opt_file_label);
            if label_create_file(opt_file_label) != 0 {
                die_with_error!(c"--file-label setup failed".as_ptr());
            }
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--dev".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--dev takes an argument".as_ptr());
            }
            op = setup_op_new(SETUP_MOUNT_DEV);
            (*op).dest = *argv.offset(1);
            opt_needs_devpts = true;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--tmpfs".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--tmpfs takes an argument".as_ptr());
            }
            op = setup_op_new(SETUP_MOUNT_TMPFS);
            (*op).dest = *argv.offset(1);
            if next_perms >= 0 {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o755;
            }
            next_perms = -1;
            (*op).size = next_size_arg;
            next_size_arg = 0;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--mqueue".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--mqueue takes an argument".as_ptr());
            }
            op = setup_op_new(SETUP_MOUNT_MQUEUE);
            (*op).dest = *argv.offset(1);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--dir".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--dir takes an argument".as_ptr());
            }
            op = setup_op_new(SETUP_MAKE_DIR);
            (*op).dest = *argv.offset(1);
            if next_perms >= 0 {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o755;
            }
            next_perms = -1;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--file".as_ptr()) == 0 {
            let mut file_fd: libc::c_int = 0;
            let mut endptr_1 = 0 as *mut libc::c_char;
            if argc < 3 {
                die!(c"--file takes two arguments".as_ptr());
            }
            file_fd = strtol(*argv.offset(1), &mut endptr_1, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_1.offset(0) as libc::c_int != 0
                || file_fd < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            op = setup_op_new(SETUP_MAKE_FILE);
            (*op).fd = file_fd;
            (*op).dest = *argv.offset(2);
            if next_perms >= 0 {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o666;
            }
            next_perms = -1;
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--bind-data".as_ptr()) == 0 {
            let mut file_fd_0: libc::c_int = 0;
            let mut endptr_2 = 0 as *mut libc::c_char;
            if argc < 3 {
                die!(c"--bind-data takes two arguments".as_ptr());
            }
            file_fd_0 = strtol(*argv.offset(1), &mut endptr_2, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_2.offset(0) as libc::c_int != 0
                || file_fd_0 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            op = setup_op_new(SETUP_MAKE_BIND_FILE);
            (*op).fd = file_fd_0;
            (*op).dest = *argv.offset(2);
            if next_perms >= 0 {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o600;
            }
            next_perms = -1;
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--ro-bind-data".as_ptr()) == 0 {
            let mut file_fd_1: libc::c_int = 0;
            let mut endptr_3 = 0 as *mut libc::c_char;
            if argc < 3 {
                die!(c"--ro-bind-data takes two arguments".as_ptr());
            }
            file_fd_1 = strtol(*argv.offset(1), &mut endptr_3, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_3.offset(0) as libc::c_int != 0
                || file_fd_1 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            op = setup_op_new(SETUP_MAKE_RO_BIND_FILE);
            (*op).fd = file_fd_1;
            (*op).dest = *argv.offset(2);
            if next_perms >= 0 {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o600;
            }
            next_perms = -1;
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--symlink".as_ptr()) == 0 {
            if argc < 3 {
                die!(c"--symlink takes two arguments".as_ptr());
            }
            op = setup_op_new(SETUP_MAKE_SYMLINK);
            (*op).source = *argv.offset(1);
            (*op).dest = *argv.offset(2);
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--lock-file".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--lock-file takes an argument".as_ptr());
            }
            lock_file_new(*argv.offset(1));
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--sync-fd".as_ptr()) == 0 {
            let mut the_fd_0: libc::c_int = 0;
            let mut endptr_4 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--sync-fd takes an argument".as_ptr());
            }
            if opt_sync_fd != -1 {
                warn_only_last_option(c"--sync-fd".as_ptr());
            }
            the_fd_0 = strtol(*argv.offset(1), &mut endptr_4, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_4.offset(0) as libc::c_int != 0
                || the_fd_0 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_sync_fd = the_fd_0;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--block-fd".as_ptr()) == 0 {
            let mut the_fd_1: libc::c_int = 0;
            let mut endptr_5 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--block-fd takes an argument".as_ptr());
            }
            if opt_block_fd != -1 {
                warn_only_last_option(c"--block-fd".as_ptr());
            }
            the_fd_1 = strtol(*argv.offset(1), &mut endptr_5, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_5.offset(0) as libc::c_int != 0
                || the_fd_1 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_block_fd = the_fd_1;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--userns-block-fd".as_ptr()) == 0 {
            let mut the_fd_2: libc::c_int = 0;
            let mut endptr_6 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--userns-block-fd takes an argument".as_ptr());
            }
            if opt_userns_block_fd != -1 {
                warn_only_last_option(c"--userns-block-fd".as_ptr());
            }
            the_fd_2 = strtol(*argv.offset(1), &mut endptr_6, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_6.offset(0) as libc::c_int != 0
                || the_fd_2 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_userns_block_fd = the_fd_2;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--info-fd".as_ptr()) == 0 {
            let mut the_fd_3: libc::c_int = 0;
            let mut endptr_7 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--info-fd takes an argument".as_ptr());
            }
            if opt_info_fd != -1 {
                warn_only_last_option(c"--info-fd".as_ptr());
            }
            the_fd_3 = strtol(*argv.offset(1), &mut endptr_7, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_7.offset(0) as libc::c_int != 0
                || the_fd_3 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_info_fd = the_fd_3;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--json-status-fd".as_ptr()) == 0 {
            let mut the_fd_4: libc::c_int = 0;
            let mut endptr_8 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--json-status-fd takes an argument".as_ptr());
            }
            if opt_json_status_fd != -1 {
                warn_only_last_option(c"--json-status-fd".as_ptr());
            }
            the_fd_4 = strtol(*argv.offset(1), &mut endptr_8, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_8.offset(0) as libc::c_int != 0
                || the_fd_4 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_json_status_fd = the_fd_4;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--seccomp".as_ptr()) == 0 {
            let mut the_fd_5: libc::c_int = 0;
            let mut endptr_9 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--seccomp takes an argument".as_ptr());
            }
            if !seccomp_programs.is_null() {
                die!(
                    c"--seccomp cannot be combined with --add-seccomp-fd".as_ptr() as *const u8
                        as *const libc::c_char,
                );
            }
            if opt_seccomp_fd != -1 {
                warn_only_last_option(c"--seccomp".as_ptr());
            }
            the_fd_5 = strtol(*argv.offset(1), &mut endptr_9, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_9.offset(0) as libc::c_int != 0
                || the_fd_5 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_seccomp_fd = the_fd_5;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--add-seccomp-fd".as_ptr()) == 0 {
            let mut the_fd_6: libc::c_int = 0;
            let mut endptr_10 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--add-seccomp-fd takes an argument".as_ptr());
            }
            if opt_seccomp_fd != -1 {
                die!(
                    c"--add-seccomp-fd cannot be combined with --seccomp".as_ptr() as *const u8
                        as *const libc::c_char,
                );
            }
            the_fd_6 = strtol(*argv.offset(1), &mut endptr_10, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_10.offset(0) as libc::c_int != 0
                || the_fd_6 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            seccomp_program_new(&mut the_fd_6);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--userns".as_ptr()) == 0 {
            let mut the_fd_7: libc::c_int = 0;
            let mut endptr_11 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--userns takes an argument".as_ptr());
            }
            if opt_userns_fd != -1 {
                warn_only_last_option(c"--userns".as_ptr());
            }
            the_fd_7 = strtol(*argv.offset(1), &mut endptr_11, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_11.offset(0) as libc::c_int != 0
                || the_fd_7 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_userns_fd = the_fd_7;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--userns2".as_ptr()) == 0 {
            let mut the_fd_8: libc::c_int = 0;
            let mut endptr_12 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--userns2 takes an argument".as_ptr());
            }
            if opt_userns2_fd != -1 {
                warn_only_last_option(c"--userns2".as_ptr());
            }
            the_fd_8 = strtol(*argv.offset(1), &mut endptr_12, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_12.offset(0) as libc::c_int != 0
                || the_fd_8 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_userns2_fd = the_fd_8;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--pidns".as_ptr()) == 0 {
            let mut the_fd_9: libc::c_int = 0;
            let mut endptr_13 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--pidns takes an argument".as_ptr());
            }
            if opt_pidns_fd != -1 {
                warn_only_last_option(c"--pidns".as_ptr());
            }
            the_fd_9 = strtol(*argv.offset(1), &mut endptr_13, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_13.offset(0) as libc::c_int != 0
                || the_fd_9 < 0
            {
                die!(c"Invalid fd: %s".as_ptr(), *argv.offset(1),);
            }
            opt_pidns_fd = the_fd_9;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--clearenv".as_ptr()) == 0 {
            xclearenv();
        } else if strcmp(arg, c"--setenv".as_ptr()) == 0 {
            if argc < 3 {
                die!(c"--setenv takes two arguments".as_ptr());
            }
            xsetenv(*argv.offset(1), *argv.offset(2), 1);
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--unsetenv".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--unsetenv takes an argument".as_ptr());
            }
            xunsetenv(*argv.offset(1));
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--uid".as_ptr()) == 0 {
            let mut the_uid: libc::c_int = 0;
            let mut endptr_14 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--uid takes an argument".as_ptr());
            }
            if opt_sandbox_uid != uid_t::MAX {
                warn_only_last_option(c"--uid".as_ptr());
            }
            the_uid = strtol(*argv.offset(1), &mut endptr_14, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_14.offset(0) as libc::c_int != 0
                || the_uid < 0
            {
                die!(c"Invalid uid: %s".as_ptr(), *argv.offset(1),);
            }
            opt_sandbox_uid = the_uid as uid_t;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--gid".as_ptr()) == 0 {
            let mut the_gid: libc::c_int = 0;
            let mut endptr_15 = 0 as *mut libc::c_char;
            if argc < 2 {
                die!(c"--gid takes an argument".as_ptr());
            }
            if opt_sandbox_gid != gid_t::MAX {
                warn_only_last_option(c"--gid".as_ptr());
            }
            the_gid = strtol(*argv.offset(1), &mut endptr_15, 10) as libc::c_int;
            if *(*argv.offset(1)).offset(0) as libc::c_int == 0
                || *endptr_15.offset(0) as libc::c_int != 0
                || the_gid < 0
            {
                die!(c"Invalid gid: %s".as_ptr(), *argv.offset(1),);
            }
            opt_sandbox_gid = the_gid as gid_t;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--hostname".as_ptr()) == 0 {
            if argc < 2 {
                die!(c"--hostname takes an argument".as_ptr());
            }
            if !opt_sandbox_hostname.is_null() {
                warn_only_last_option(c"--hostname".as_ptr());
            }
            op = setup_op_new(SETUP_SET_HOSTNAME);
            (*op).dest = *argv.offset(1);
            (*op).flags = NO_CREATE_DEST;
            opt_sandbox_hostname = *argv.offset(1);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--new-session".as_ptr()) == 0 {
            opt_new_session = true;
        } else if strcmp(arg, c"--die-with-parent".as_ptr()) == 0 {
            opt_die_with_parent = true;
        } else if strcmp(arg, c"--as-pid-1".as_ptr()) == 0 {
            opt_as_pid_1 = true;
        } else if strcmp(arg, c"--cap-add".as_ptr()) == 0 {
            let mut cap: cap_value_t = 0;
            if argc < 2 {
                die!(c"--cap-add takes an argument".as_ptr());
            }
            opt_cap_add_or_drop_used = true;
            if strcasecmp(*argv.offset(1), c"ALL".as_ptr()) == 0 {
                requested_caps[1] = 0xffffffff as libc::c_uint;
                requested_caps[0] = requested_caps[1];
            } else {
                if cap_from_name(*argv.offset(1), &mut cap) < 0 {
                    die!(c"unknown cap: %s".as_ptr(), *argv.offset(1),);
                }
                if cap < 32 {
                    requested_caps[0] =
                        (requested_caps[0] as libc::c_long | (1) << (cap & 31)) as u32;
                } else {
                    requested_caps[1] =
                        (requested_caps[1] as libc::c_long | (1) << (cap - 32 - 32 & 31)) as u32;
                }
            }
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--cap-drop".as_ptr()) == 0 {
            let mut cap_0: cap_value_t = 0;
            if argc < 2 {
                die!(c"--cap-drop takes an argument".as_ptr());
            }
            opt_cap_add_or_drop_used = true;
            if strcasecmp(*argv.offset(1), c"ALL".as_ptr()) == 0 {
                requested_caps[1] = 0;
                requested_caps[0] = requested_caps[1];
            } else {
                if cap_from_name(*argv.offset(1), &mut cap_0) < 0 {
                    die!(c"unknown cap: %s".as_ptr(), *argv.offset(1),);
                }
                if cap_0 < 32 {
                    requested_caps[0] =
                        (requested_caps[0] as libc::c_long & !((1) << (cap_0 & 31))) as u32;
                } else {
                    requested_caps[1] = (requested_caps[1] as libc::c_long
                        & !((1) << (cap_0 - 32 - 32 & 31)))
                        as u32;
                }
            }
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--perms".as_ptr()) == 0 {
            let mut perms: libc::c_ulong = 0;
            let mut endptr_16 = std::ptr::null_mut() as *mut libc::c_char;
            if argc < 2 {
                die!(c"--perms takes an argument".as_ptr());
            }
            if next_perms != -1 {
                die!(
                    c"--perms given twice for the same action".as_ptr() as *const u8
                        as *const libc::c_char
                );
            }
            perms = strtoul(*argv.offset(1), &mut endptr_16, 8);
            if *(*argv.offset(1)).offset(0) as libc::c_int == '\0' as i32
                || endptr_16.is_null()
                || *endptr_16 != '\0' as i8
                || perms > 0o7777
            {
                die!(
                    c"--perms takes an octal argument <= 07777".as_ptr() as *const u8
                        as *const libc::c_char
                );
            }
            next_perms = perms as libc::c_int;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--size".as_ptr()) == 0 {
            let mut size: libc::c_ulonglong = 0;
            let mut endptr_17 = std::ptr::null_mut() as *mut libc::c_char;
            if is_privileged {
                die!(
                    c"The --size option is not permitted in setuid mode".as_ptr() as *const u8
                        as *const libc::c_char,
                );
            }
            if argc < 2 {
                die!(c"--size takes an argument".as_ptr());
            }
            if next_size_arg != 0 {
                die!(c"--size given twice for the same action".as_ptr());
            }
            errno!() = 0;
            size = strtoull(*argv.offset(1), &mut endptr_17, 0);
            if errno!() != 0
                || libc::isdigit(*(*argv.offset(1)) as i32) as libc::c_int as libc::c_ushort
                    as libc::c_int
                    == 0
                || endptr_17.is_null()
                || *endptr_17 != '\0' as i8
                || size == 0
            {
                die!(
                    c"--size takes a non-zero number of bytes".as_ptr() as *const u8
                        as *const libc::c_char
                );
            }
            if size > privilged_op::MAX_TMPFS_BYTES.get() as _ {
                die!(
                    c"--size (for tmpfs) is limited to %zu".as_ptr(),
                    privilged_op::MAX_TMPFS_BYTES,
                );
            }
            next_size_arg = size as size_t;
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, c"--chmod".as_ptr()) == 0 {
            let mut perms_0: libc::c_ulong = 0;
            let mut endptr_18 = std::ptr::null_mut() as *mut libc::c_char;
            if argc < 3 {
                die!(c"--chmod takes two arguments".as_ptr());
            }
            perms_0 = strtoul(*argv.offset(1), &mut endptr_18, 8);
            if *(*argv.offset(1)).offset(0) as libc::c_int == '\0' as i32
                || endptr_18.is_null()
                || *endptr_18 != '\0' as i8
                || perms_0 > 0o7777
            {
                die!(
                    c"--chmod takes an octal argument <= 07777".as_ptr() as *const u8
                        as *const libc::c_char
                );
            }
            op = setup_op_new(SETUP_CHMOD);
            (*op).flags = NO_CREATE_DEST;
            (*op).perms = perms_0 as _;
            (*op).dest = *argv.offset(2);
            argv = argv.offset(2);
            argc -= 2;
        } else if strcmp(arg, c"--".as_ptr()) == 0 {
            argv = argv.offset(1);
            argc -= 1;
            break;
        } else {
            if !(*arg as libc::c_int == '-' as i32) {
                break;
            }
            die!(c"Unknown option %s".as_ptr(), arg,);
        }
        if is_modifier_option(arg) == 0 && next_perms >= 0 {
            die!(
                c"--perms must be followed by an option that creates a file".as_ptr() as *const u8
                    as *const libc::c_char,
            );
        }
        if is_modifier_option(arg) == 0 && next_size_arg != 0 {
            die!(c"--size must be followed by --tmpfs".as_ptr());
        }
        if strcmp(arg, c"--overlay-src".as_ptr()) != 0 && next_overlay_src_count > 0 {
            die!(
                c"--overlay-src must be followed by another --overlay-src or one of --overlay, --tmp-overlay, or --ro-overlay".as_ptr()
                    as *const u8 as *const libc::c_char,
            );
        }
        argv = argv.offset(1);
        argc -= 1;
    }
    *argcp = argc;
    *argvp = argv;
}

unsafe fn parse_args(argcp: *mut libc::c_int, argvp: *mut *mut *const libc::c_char) {
    let mut total_parsed_argc = *argcp;
    parse_args_recurse(argcp, argvp, false, &mut total_parsed_argc);
    if next_overlay_src_count > 0 {
        die!(
            c"--overlay-src must be followed by another --overlay-src or one of --overlay, --tmp-overlay, or --ro-overlay".as_ptr()
                as *const u8 as *const libc::c_char,
        );
    }
}

unsafe fn read_overflowids() {
    let mut uid_data = std::ptr::null_mut() as *mut libc::c_char;
    let mut gid_data = std::ptr::null_mut() as *mut libc::c_char;
    uid_data = load_file_at(AT_FDCWD, c"/proc/sys/kernel/overflowuid".as_ptr());
    if uid_data.is_null() {
        die_with_error!(c"Can't read /proc/sys/kernel/overflowuid".as_ptr(),);
    }
    overflow_uid = strtol(uid_data, std::ptr::null_mut() as *mut *mut libc::c_char, 10) as uid_t;
    if overflow_uid == 0 {
        die!(c"Can't parse /proc/sys/kernel/overflowuid".as_ptr());
    }
    gid_data = load_file_at(AT_FDCWD, c"/proc/sys/kernel/overflowgid".as_ptr());
    if gid_data.is_null() {
        die_with_error!(c"Can't read /proc/sys/kernel/overflowgid".as_ptr(),);
    }
    overflow_gid = strtol(gid_data, std::ptr::null_mut() as *mut *mut libc::c_char, 10) as gid_t;
    if overflow_gid == 0 {
        die!(c"Can't parse /proc/sys/kernel/overflowgid".as_ptr());
    }
}

unsafe fn namespace_ids_read(pid: pid_t) {
    let mut dir = std::ptr::null_mut() as *mut libc::c_char;
    let mut ns_fd = -1;
    let mut info = 0 as *mut NsInfo;
    dir = xasprintf(c"%d/ns".as_ptr(), pid);
    ns_fd = ({
        let mut __result: libc::c_long = 0;
        loop {
            __result = openat(proc_fd, dir, 0o10000000) as libc::c_long;
            if !(__result == -1 && errno!() == libc::EINTR) {
                break;
            }
        }
        __result
    }) as libc::c_int;
    if ns_fd < 0 {
        die_with_error!(c"open /proc/%s/ns failed".as_ptr(), dir,);
    }
    info = ns_infos.as_mut_ptr();
    while !((*info).name).is_null() {
        let do_unshare = (*info).do_unshare;
        let mut st = std::mem::zeroed();
        let mut r: libc::c_int = 0;
        if !(!do_unshare.is_null() && *do_unshare as bool == false) {
            r = fstatat(ns_fd, (*info).name, &mut st, 0);
            if !(r != 0) {
                (*info).id = st.st_ino;
            }
        }
        info = info.offset(1);
    }
}

unsafe fn namespace_ids_write(fd: libc::c_int, in_json: bool) {
    let mut info = 0 as *mut NsInfo;
    info = ns_infos.as_mut_ptr();
    while !((*info).name).is_null() {
        let mut output = std::ptr::null_mut() as *mut libc::c_char;
        let mut indent = 0 as *const libc::c_char;
        let mut nsid: uintmax_t = 0;
        nsid = (*info).id;
        if !(nsid == 0) {
            indent = if in_json as libc::c_int != 0 {
                c" ".as_ptr()
            } else {
                c"\n    ".as_ptr()
            };
            output = xasprintf(
                c",%s\"%s-namespace\": %ju".as_ptr(),
                indent,
                (*info).name,
                nsid,
            );
            dump_info(fd, output, true);
        }
        info = info.offset(1);
    }
}

pub unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut old_umask: mode_t = 0;
    let mut base_path = std::ptr::null_mut() as *const libc::c_char;
    let mut clone_flags: libc::c_int = 0;
    let mut old_cwd = std::ptr::null_mut() as *mut libc::c_char;
    let mut pid: pid_t = 0;
    let mut event_fd = -1;
    let mut child_wait_fd = -1;
    let mut setup_finished_pipe: [libc::c_int; 2] = [-1, -1];
    let mut new_cwd = 0 as *const libc::c_char;
    let mut ns_uid: uid_t = 0;
    let mut ns_gid: gid_t = 0;
    let mut sbuf = std::mem::zeroed();
    let mut val: u64 = 0;
    let mut res: libc::c_int = 0;
    let mut args_data = std::ptr::null_mut() as *mut libc::c_char;
    let mut intermediate_pids_sockets: [libc::c_int; 2] = [-1, -1];
    let mut exec_path = std::ptr::null_mut() as *const libc::c_char;
    let mut i: libc::c_int = 0;
    if argc == 2 && strcmp(*argv.offset(1), c"--version".as_ptr()) == 0 {
        print_version_and_exit();
    }
    real_uid = getuid();
    real_gid = getgid();
    acquire_privs();
    if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
        die_with_error!(c"prctl(PR_SET_NO_NEW_PRIVS) failed".as_ptr());
    }
    read_overflowids();
    argv0 = *argv.offset(0);
    if isatty(1) != 0 {
        host_tty_dev = ttyname(1);
    }
    argv = argv.offset(1);
    argc -= 1;
    if argc <= 0 {
        usage(EXIT_FAILURE, stderr);
    }
    parse_args(
        &mut argc,
        &mut argv as *mut *mut *mut libc::c_char as *mut *mut *const libc::c_char,
    );
    args_data = opt_args_data;
    opt_args_data = std::ptr::null_mut() as *mut libc::c_char;
    if (requested_caps[0] != 0 || requested_caps[1] != 0) && is_privileged as libc::c_int != 0 {
        die!(
            c"--cap-add in setuid mode can be used only by root".as_ptr() as *const u8
                as *const libc::c_char,
        );
    }
    if opt_userns_block_fd != -1 && !opt_unshare_user {
        die!(c"--userns-block-fd requires --unshare-user".as_ptr());
    }
    if opt_userns_block_fd != -1 && opt_info_fd == -1 {
        die!(c"--userns-block-fd requires --info-fd".as_ptr());
    }
    if opt_userns_fd != -1 && opt_unshare_user as libc::c_int != 0 {
        die!(c"--userns not compatible --unshare-user".as_ptr());
    }
    if opt_userns_fd != -1 && opt_unshare_user_try as libc::c_int != 0 {
        die!(c"--userns not compatible --unshare-user-try".as_ptr());
    }
    if opt_disable_userns as libc::c_int != 0 && !opt_unshare_user {
        die!(c"--disable-userns requires --unshare-user".as_ptr());
    }
    if opt_disable_userns as libc::c_int != 0 && opt_userns_block_fd != -1 {
        die!(
            c"--disable-userns is not compatible with  --userns-block-fd".as_ptr() as *const u8
                as *const libc::c_char,
        );
    }
    if opt_userns_fd != -1 && is_privileged as libc::c_int != 0 {
        die!(c"--userns doesn't work in setuid mode".as_ptr());
    }
    if opt_userns2_fd != -1 && is_privileged as libc::c_int != 0 {
        die!(c"--userns2 doesn't work in setuid mode".as_ptr());
    }
    if !is_privileged && getuid() != 0 && opt_userns_fd == -1 {
        opt_unshare_user = true;
    }
    if opt_unshare_user_try as libc::c_int != 0
        && stat(c"/proc/self/ns/user".as_ptr(), &mut sbuf) == 0
    {
        let mut disabled = false;
        if stat(
            c"/sys/module/user_namespace/parameters/enable".as_ptr(),
            &mut sbuf,
        ) == 0
        {
            let mut enable = std::ptr::null_mut() as *mut libc::c_char;
            enable = load_file_at(
                AT_FDCWD,
                c"/sys/module/user_namespace/parameters/enable".as_ptr() as *const u8
                    as *const libc::c_char,
            );
            if !enable.is_null() && *enable.offset(0) as libc::c_int == 'N' as i32 {
                disabled = true;
            }
        }
        if stat(c"/proc/sys/user/max_user_namespaces".as_ptr(), &mut sbuf) == 0 {
            let mut max_user_ns = std::ptr::null_mut() as *mut libc::c_char;
            max_user_ns = load_file_at(AT_FDCWD, c"/proc/sys/user/max_user_namespaces".as_ptr());
            if !max_user_ns.is_null() && strcmp(max_user_ns, c"0\n".as_ptr()) == 0 {
                disabled = true;
            }
        }
        if !disabled {
            opt_unshare_user = true;
        }
    }
    if argc <= 0 {
        usage(EXIT_FAILURE, stderr);
    }
    if opt_sandbox_uid == uid_t::MAX {
        opt_sandbox_uid = real_uid;
    }
    if opt_sandbox_gid == gid_t::MAX {
        opt_sandbox_gid = real_gid;
    }
    if !opt_unshare_user && opt_userns_fd == -1 && opt_sandbox_uid != real_uid {
        die!(
            c"Specifying --uid requires --unshare-user or --userns".as_ptr() as *const u8
                as *const libc::c_char,
        );
    }
    if !opt_unshare_user && opt_userns_fd == -1 && opt_sandbox_gid != real_gid {
        die!(
            c"Specifying --gid requires --unshare-user or --userns".as_ptr() as *const u8
                as *const libc::c_char,
        );
    }
    if !opt_unshare_uts && !opt_sandbox_hostname.is_null() {
        die!(c"Specifying --hostname requires --unshare-uts".as_ptr());
    }
    if opt_as_pid_1 && !opt_unshare_pid {
        die!(c"Specifying --as-pid-1 requires --unshare-pid".as_ptr());
    }
    if opt_as_pid_1 && !lock_files.is_null() {
        die!(
            c"Specifying --as-pid-1 and --lock-file is not permitted".as_ptr() as *const u8
                as *const libc::c_char,
        );
    }
    proc_fd = retry!(open(c"/proc".as_ptr(), 0o10000000));
    if proc_fd == -1 {
        die_with_error!(c"Can't open /proc".as_ptr());
    }
    base_path = c"/tmp".as_ptr();
    if opt_unshare_pid as libc::c_int != 0 && !opt_as_pid_1 {
        event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if event_fd == -1 {
            die_with_error!(c"eventfd()".as_ptr());
        }
    }
    block_sigchild();
    clone_flags = SIGCHLD | CLONE_NEWNS;
    if opt_unshare_user {
        clone_flags |= CLONE_NEWUSER;
    }
    if opt_unshare_pid as libc::c_int != 0 && opt_pidns_fd == -1 {
        clone_flags |= CLONE_NEWPID;
    }
    if opt_unshare_net {
        clone_flags |= CLONE_NEWNET;
    }
    if opt_unshare_ipc {
        clone_flags |= CLONE_NEWIPC;
    }
    if opt_unshare_uts {
        clone_flags |= CLONE_NEWUTS;
    }
    if opt_unshare_cgroup {
        if stat(c"/proc/self/ns/cgroup".as_ptr(), &mut sbuf) != 0 {
            if errno!() == ENOENT {
                die!(
                    c"Cannot create new cgroup namespace because the kernel does not support it"
                        .as_ptr() as *const u8 as *const libc::c_char,
                );
            } else {
                die_with_error!(c"stat on /proc/self/ns/cgroup failed".as_ptr(),);
            }
        }
        clone_flags |= CLONE_NEWCGROUP;
    }
    if opt_unshare_cgroup_try {
        opt_unshare_cgroup = stat(c"/proc/self/ns/cgroup".as_ptr(), &mut sbuf) == 0;
        if opt_unshare_cgroup {
            clone_flags |= CLONE_NEWCGROUP;
        }
    }
    child_wait_fd = eventfd(0, EFD_CLOEXEC);
    if child_wait_fd == -1 {
        die_with_error!(c"eventfd()".as_ptr());
    }
    if opt_json_status_fd != -1 {
        let mut ret: libc::c_int = 0;
        ret = pipe2(setup_finished_pipe.as_mut_ptr(), O_CLOEXEC);
        if ret == -1 {
            die_with_error!(c"pipe2()".as_ptr());
        }
    }
    if opt_userns_fd > 0 && setns(opt_userns_fd, CLONE_NEWUSER) != 0 {
        if errno!() == libc::EINVAL {
            die!(
                c"Joining the specified user namespace failed, it might not be a descendant of the current user namespace.".as_ptr()
                    as *const u8 as *const libc::c_char,
            );
        }
        die_with_error!(c"Joining specified user namespace failed".as_ptr(),);
    }
    if opt_pidns_fd != -1 {
        prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
        create_pid_socketpair(intermediate_pids_sockets.as_mut_ptr());
    }
    pid = raw_clone(clone_flags as libc::c_ulong, std::ptr::null_mut());
    if pid == -1 {
        if opt_unshare_user {
            if errno!() == libc::EINVAL {
                die!(
                    c"Creating new namespace failed, likely because the kernel does not support user namespaces.  bwrap must be installed setuid on such systems.".as_ptr()
                        as *const u8 as *const libc::c_char,
                );
            } else if errno!() == EPERM && !is_privileged {
                die!(
                    c"No permissions to creating new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'.".as_ptr()
                        as *const u8 as *const libc::c_char,
                );
            }
        }
        if errno!() == libc::ENOSPC {
            die!(
                c"Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)".as_ptr()
                    as *const u8 as *const libc::c_char,
            );
        }
        die_with_error!(c"Creating new namespace failed".as_ptr());
    }
    ns_uid = opt_sandbox_uid;
    ns_gid = opt_sandbox_gid;
    if pid != 0 {
        if intermediate_pids_sockets[0] != -1 {
            close(intermediate_pids_sockets[1]);
            pid = read_pid_from_socket(intermediate_pids_sockets[0]);
            close(intermediate_pids_sockets[0]);
        }
        namespace_ids_read(pid);
        if is_privileged as libc::c_int != 0
            && opt_unshare_user as libc::c_int != 0
            && opt_userns_block_fd == -1
        {
            write_uid_gid_map(
                ns_uid,
                real_uid,
                ns_gid,
                real_gid,
                pid,
                true,
                opt_needs_devpts,
            );
        }
        if opt_userns2_fd > 0 && setns(opt_userns2_fd, CLONE_NEWUSER) != 0 {
            die_with_error!(c"Setting userns2 failed".as_ptr());
        }
        drop_privs(false, false);
        handle_die_with_parent();
        if opt_info_fd != -1 {
            let output = xasprintf(c"{\n    \"child-pid\": %i".as_ptr(), pid);
            dump_info(opt_info_fd, output, true);
            namespace_ids_write(opt_info_fd, false);
            dump_info(opt_info_fd, c"\n}\n".as_ptr(), true);
            close(opt_info_fd);
        }
        if opt_json_status_fd != -1 {
            let output_0 = xasprintf(c"{ \"child-pid\": %i".as_ptr(), pid);
            dump_info(opt_json_status_fd, output_0, true);
            namespace_ids_write(opt_json_status_fd, true);
            dump_info(opt_json_status_fd, c" }\n".as_ptr(), true);
        }
        if opt_userns_block_fd != -1 {
            let mut b: [libc::c_char; 1] = [0; 1];
            retry!(read(
                opt_userns_block_fd,
                b.as_mut_ptr() as *mut libc::c_void,
                1
            ));
            retry!(read(
                opt_userns_block_fd,
                b.as_mut_ptr() as *mut libc::c_void,
                1
            ));
            close(opt_userns_block_fd);
        }
        val = 1;
        res = retry!(write(
            child_wait_fd,
            &mut val as *mut u64 as *const libc::c_void,
            8,
        )) as _;
        close(child_wait_fd);
        return monitor_child(event_fd, pid, setup_finished_pipe[0]);
    }
    if opt_pidns_fd > 0 {
        if setns(opt_pidns_fd, CLONE_NEWPID) != 0 {
            die_with_error!(c"Setting pidns failed".as_ptr());
        }
        fork_intermediate_child();
        if opt_unshare_pid {
            if unshare(CLONE_NEWPID) != 0 {
                die_with_error!(c"unshare pid ns".as_ptr());
            }
            fork_intermediate_child();
        }
        close(intermediate_pids_sockets[0]);
        send_pid_on_socket(intermediate_pids_sockets[1]);
        close(intermediate_pids_sockets[1]);
    }
    if opt_info_fd != -1 {
        close(opt_info_fd);
    }
    if opt_json_status_fd != -1 {
        close(opt_json_status_fd);
    }
    res = read(child_wait_fd, &mut val as *mut u64 as *mut libc::c_void, 8) as libc::c_int;
    close(child_wait_fd);
    switch_to_user_with_privs();
    if opt_unshare_net {
        loopback_setup().unwrap();
    }
    ns_uid = opt_sandbox_uid;
    ns_gid = opt_sandbox_gid;
    if !is_privileged && opt_unshare_user as libc::c_int != 0 && opt_userns_block_fd == -1 {
        if opt_needs_devpts {
            ns_uid = 0;
            ns_gid = 0;
        }
        write_uid_gid_map(ns_uid, real_uid, ns_gid, real_gid, -1, true, false);
    }
    old_umask = umask(0);
    resolve_symlinks_in_ops();
    if mount(
        std::ptr::null_mut() as *const libc::c_char,
        c"/".as_ptr(),
        std::ptr::null_mut() as *const libc::c_char,
        (MS_SILENT | MS_SLAVE | MS_REC) as libc::c_ulong,
        std::ptr::null_mut() as *const libc::c_void,
    ) < 0
    {
        die_with_mount_error!(c"Failed to make / slave".as_ptr());
    }
    if mount(
        c"tmpfs".as_ptr(),
        base_path,
        c"tmpfs".as_ptr(),
        (MS_NODEV | MS_NOSUID) as libc::c_ulong,
        std::ptr::null_mut() as *const libc::c_void,
    ) != 0
    {
        die_with_mount_error!(c"Failed to mount tmpfs".as_ptr());
    }
    old_cwd = get_current_dir_name();
    if chdir(base_path) != 0 {
        die_with_error!(c"chdir base_path".as_ptr());
    }
    if mkdir(c"newroot".as_ptr(), 0o755) != 0 {
        die_with_error!(c"Creating newroot failed".as_ptr());
    }
    if mount(
        c"newroot".as_ptr(),
        c"newroot".as_ptr(),
        std::ptr::null_mut() as *const libc::c_char,
        (MS_SILENT as libc::c_uint
            | MS_MGC_VAL as libc::c_uint
            | MS_BIND as libc::c_uint
            | MS_REC as libc::c_uint) as libc::c_ulong,
        std::ptr::null_mut() as *const libc::c_void,
    ) < 0
    {
        die_with_mount_error!(c"setting up newroot bind".as_ptr());
    }
    if mkdir(c"oldroot".as_ptr(), 0o755) != 0 {
        die_with_error!(c"Creating oldroot failed".as_ptr());
    }
    i = 0;
    while i < opt_tmp_overlay_count {
        let mut dirname = 0 as *mut libc::c_char;
        dirname = xasprintf(c"tmp-overlay-upper-%d".as_ptr(), i);
        if mkdir(dirname, 0o755) != 0 {
            die_with_error!(c"Creating --tmp-overlay upperdir failed".as_ptr(),);
        }
        free(dirname as *mut libc::c_void);
        dirname = xasprintf(c"tmp-overlay-work-%d".as_ptr(), i);
        if mkdir(dirname, 0o755) != 0 {
            die_with_error!(c"Creating --tmp-overlay workdir failed".as_ptr(),);
        }
        free(dirname as *mut libc::c_void);
        i += 1;
    }
    if pivot_root(base_path, c"oldroot".as_ptr()) != 0 {
        die_with_error!(c"pivot_root".as_ptr());
    }
    if chdir(c"/".as_ptr()) != 0 {
        die_with_error!(c"chdir / (base path)".as_ptr());
    }
    if is_privileged {
        let mut child: pid_t = 0;
        let mut privsep_sockets: [libc::c_int; 2] = [0; 2];
        if socketpair(
            AF_UNIX,
            SOCK_SEQPACKET | SOCK_CLOEXEC,
            0,
            privsep_sockets.as_mut_ptr(),
        ) != 0
        {
            die_with_error!(c"Can't create privsep socket".as_ptr());
        }
        child = fork();
        if child == -1 {
            die_with_error!(c"Can't fork unprivileged helper".as_ptr());
        }
        if child == 0 {
            drop_privs(false, true);
            close(privsep_sockets[0]);
            setup_newroot(opt_unshare_pid, privsep_sockets[1]);
            exit(0);
        } else {
            fn handle_priv_op<'fd, 'buf>(
                fd: BorrowedFd<'fd>,
                buffer: &'buf mut [u8],
            ) -> Result<(bool, &'buf mut [u8]), ()> {
                let bytes = nix_retry!(nix::unistd::read(fd.as_raw_fd(), &mut buffer[..]))
                    .map_err(|_| ())?;
                let msg: PrivilegedOp = postcard::from_bytes(&buffer[..bytes]).map_err(|_| ())?;

                let end = matches!(msg, PrivilegedOp::Done);
                let ret = privileged_op(-1, msg);
                buffer.fill(0);

                postcard::to_slice(&ret, &mut buffer[..])
                    .map_err(|_| ())
                    .map(|b| (end, b))
            }

            let unpriv_socket = unsafe { OwnedFd::from_raw_fd(privsep_sockets[0]) };
            let mut buffer = vec![0; 8096];
            let _ = nix::unistd::close(privsep_sockets[1]);
            loop {
                let (end, buf) = match handle_priv_op(unpriv_socket.as_fd(), &mut buffer[..]) {
                    Ok(o) => o,
                    Err(()) => (
                        true,
                        postcard::to_slice(
                            &Result::<(), _>::Err(
                                PrivilegedOpError::PrivilegedProcessCommunicationError,
                            ),
                            &mut buffer[..],
                        )
                        .unwrap(),
                    ),
                };
                let Ok(_) = nix_retry!(nix::unistd::write(unpriv_socket.as_fd(), buf)) else {
                    break;
                };
                if end {
                    break;
                };
            }

            let _ = nix_retry!(nix::sys::wait::waitpid(
                Some(nix::unistd::Pid::from_raw(child)),
                None
            ));
        }
    } else {
        setup_newroot(opt_unshare_pid, -1);
    }
    close_ops_fd();
    if mount(
        c"oldroot".as_ptr(),
        c"oldroot".as_ptr(),
        std::ptr::null_mut() as *const libc::c_char,
        (MS_SILENT | MS_REC | MS_PRIVATE) as libc::c_ulong,
        std::ptr::null_mut() as *const libc::c_void,
    ) != 0
    {
        die_with_mount_error!(c"Failed to make old root rprivate".as_ptr(),);
    }
    if umount2(c"oldroot".as_ptr(), MNT_DETACH) != 0 {
        die_with_error!(c"unmount old root".as_ptr());
    }
    let oldrootfd = retry!(open(c"/".as_ptr(), 0o200000 | 0));
    if oldrootfd < 0 {
        die_with_error!(c"can't open /".as_ptr());
    }
    if chdir(c"/newroot".as_ptr()) != 0 {
        die_with_error!(c"chdir /newroot".as_ptr());
    }
    if pivot_root(c".".as_ptr(), c".".as_ptr()) != 0 {
        die_with_error!(c"pivot_root(/newroot)".as_ptr());
    }
    if fchdir(oldrootfd) < 0 {
        die_with_error!(c"fchdir to oldroot".as_ptr());
    }
    if umount2(c".".as_ptr(), MNT_DETACH) < 0 {
        die_with_error!(c"umount old root".as_ptr());
    }
    if chdir(c"/".as_ptr()) != 0 {
        die_with_error!(c"chdir /".as_ptr());
    }
    if opt_userns2_fd > 0 && setns(opt_userns2_fd, CLONE_NEWUSER) != 0 {
        die_with_error!(c"Setting userns2 failed".as_ptr());
    }
    if opt_unshare_user as libc::c_int != 0
        && opt_userns_block_fd == -1
        && (ns_uid != opt_sandbox_uid
            || ns_gid != opt_sandbox_gid
            || opt_disable_userns as libc::c_int != 0)
    {
        if opt_disable_userns {
            let mut sysctl_fd = -1;
            sysctl_fd = retry!(openat(
                proc_fd,
                c"sys/user/max_user_namespaces".as_ptr(),
                0o1
            ));
            if sysctl_fd < 0 {
                die_with_error!(c"cannot open /proc/sys/user/max_user_namespaces".as_ptr()
                    as *const u8 as *const libc::c_char,);
            }
            if write_to_fd(sysctl_fd, c"1".as_ptr(), 1) < 0 {
                die_with_error!(c"sysctl user.max_user_namespaces = 1".as_ptr(),);
            }
        }
        if unshare(CLONE_NEWUSER) != 0 {
            die_with_error!(c"unshare user ns".as_ptr());
        }
        drop_cap_bounding_set(false);
        write_uid_gid_map(
            opt_sandbox_uid,
            ns_uid,
            opt_sandbox_gid,
            ns_gid,
            -1,
            false,
            false,
        );
    }
    if opt_disable_userns as libc::c_int != 0 || opt_assert_userns_disabled as libc::c_int != 0 {
        res = unshare(CLONE_NEWUSER);
        if res == 0 {
            die!(
                c"creation of new user namespaces was not disabled as requested".as_ptr()
                    as *const u8 as *const libc::c_char,
            );
        }
    }
    drop_privs(!is_privileged, true);
    if opt_block_fd != -1 {
        let mut b_0: [libc::c_char; 1] = [0; 1];
        retry!(read(opt_block_fd, b_0.as_mut_ptr() as *mut libc::c_void, 1));
        retry!(read(opt_block_fd, b_0.as_mut_ptr() as *mut libc::c_void, 1));
        close(opt_block_fd);
    }
    if opt_seccomp_fd != -1 {
        assert!(seccomp_programs.is_null())
    }
    umask(old_umask);
    new_cwd = c"/".as_ptr();
    if !opt_chdir_path.is_null() {
        if chdir(opt_chdir_path) != 0 {
            die_with_error!(c"Can't chdir to %s".as_ptr(), opt_chdir_path,);
        }
        new_cwd = opt_chdir_path;
    } else if chdir(old_cwd) == 0 {
        new_cwd = old_cwd;
    } else {
        let home: *const libc::c_char = getenv(c"HOME".as_ptr());
        if !home.is_null() && chdir(home) == 0 {
            new_cwd = home;
        }
    }
    xsetenv(c"PWD".as_ptr(), new_cwd, 1);
    free(old_cwd as *mut libc::c_void);
    if opt_new_session as libc::c_int != 0 && setsid() == -1 {
        die_with_error!(c"setsid".as_ptr());
    }
    if label_exec(opt_exec_label) == -1 {
        die_with_error!(c"label_exec %s".as_ptr(), *argv.offset(0),);
    }
    if !opt_as_pid_1
        && (opt_unshare_pid as libc::c_int != 0 || !lock_files.is_null() || opt_sync_fd != -1)
    {
        pid = fork();
        if pid == -1 {
            die_with_error!(c"Can't fork for pid 1".as_ptr());
        }
        if pid != 0 {
            drop_all_caps(false);
            let mut dont_close: [libc::c_int; 3] = [0; 3];
            let mut j = 0;
            if event_fd != -1 {
                let fresh6 = j;
                j = j + 1;
                dont_close[fresh6] = event_fd;
            }
            if opt_sync_fd != -1 {
                let fresh7 = j;
                j = j + 1;
                dont_close[fresh7] = opt_sync_fd;
            }
            let fresh8 = j;
            j = j + 1;
            dont_close[fresh8] = -1;
            fdwalk(
                proc_fd,
                Some(close_extra_fds as unsafe fn(*mut libc::c_void, libc::c_int) -> libc::c_int),
                dont_close.as_mut_ptr() as *mut libc::c_void,
            );
            return do_init(event_fd, pid);
        }
    }
    if proc_fd != -1 {
        close(proc_fd);
    }
    if !opt_as_pid_1 && opt_sync_fd != -1 {
        close(opt_sync_fd);
    }
    unblock_sigchild();
    handle_die_with_parent();
    if !is_privileged {
        set_ambient_capabilities();
    }
    seccomp_programs_apply();
    if setup_finished_pipe[1] != -1 {
        let mut data = 0;
        res = write_to_fd(setup_finished_pipe[1], &mut data, 1);
    }
    exec_path = *argv.offset(0);
    if !opt_argv0.is_null() {
        let ref mut fresh9 = *argv.offset(0);
        *fresh9 = opt_argv0 as *mut libc::c_char;
    }
    if execvp(exec_path, argv as *const *const libc::c_char) == -1 {
        if setup_finished_pipe[1] != -1 {
            let saved_errno = errno!();
            let mut data_0 = 0;
            res = write_to_fd(setup_finished_pipe[1], &mut data_0, 1);
            errno!() = saved_errno;
        }
        die_with_error!(c"execvp %s".as_ptr(), exec_path,);
    }
    return 0;
}
