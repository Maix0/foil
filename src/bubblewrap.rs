use ::libc;
use libc::{fcntl, printf, uintmax_t, AT_FDCWD, MNT_DETACH, MS_MGC_VAL, S_IFDIR};

use crate::*;
use crate::{
    bind_mount::bind_mount,
    types::*,
    utils::{
        copy_file_data, create_file, create_pid_socketpair, die_unless_label_valid, ensure_dir,
        ensure_file, fdwalk, fork_intermediate_child, get_file_mode, get_newroot_path,
        label_create_file, label_exec, label_mount, load_file_data, mkdir_with_parents, pivot_root,
        raw_clone, read_pid_from_socket, send_pid_on_socket, strappend,
        strappend_escape_for_mount_options, strconcat, strconcat3, write_file_at, write_to_fd,
        xcalloc, xclearenv, xsetenv, xunsetenv,
    },
};

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
    pub flags: u32,
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

pub const MAX_TMPFS_BYTES: libc::c_ulong = (SIZE_MAX >> 1) as libc::c_ulong;

static mut real_uid: uid_t = 0;
static mut real_gid: gid_t = 0;
static mut overflow_uid: uid_t = 0;
static mut overflow_gid: gid_t = 0;
static mut is_privileged: bool = false;
static mut argv0: *const libc::c_char = 0 as *const libc::c_char;
static mut host_tty_dev: *const libc::c_char = 0 as *const libc::c_char;
static mut proc_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_exec_label: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
static mut opt_file_label: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
static mut opt_as_pid_1: bool = false;
static mut opt_argv0: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
static mut opt_chdir_path: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
static mut opt_assert_userns_disabled: bool = false;
static mut opt_disable_userns: bool = false;
static mut opt_unshare_user: bool = false;
static mut opt_unshare_user_try: bool = false;
static mut opt_unshare_pid: bool = false;
static mut opt_unshare_ipc: bool = false;
static mut opt_unshare_net: bool = false;
static mut opt_unshare_uts: bool = false;
static mut opt_unshare_cgroup: bool = false;
static mut opt_unshare_cgroup_try: bool = false;
static mut opt_needs_devpts: bool = false;
static mut opt_new_session: bool = false;
static mut opt_die_with_parent: bool = false;
static mut opt_sandbox_uid: uid_t = -(1 as libc::c_int) as uid_t;
static mut opt_sandbox_gid: gid_t = -(1 as libc::c_int) as gid_t;
static mut opt_sync_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_block_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_userns_block_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_info_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_json_status_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_seccomp_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_sandbox_hostname: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
static mut opt_args_data: *mut libc::c_char = std::ptr::null_mut() as *mut libc::c_char;
static mut opt_userns_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_userns2_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_pidns_fd: libc::c_int = -(1 as libc::c_int);
static mut opt_tmp_overlay_count: libc::c_int = 0 as libc::c_int;
static mut next_perms: libc::c_int = -(1 as libc::c_int);
static mut next_size_arg: size_t = 0 as libc::c_int as size_t;
static mut next_overlay_src_count: libc::c_int = 0 as libc::c_int;

static mut ns_infos: [NsInfo; 7] = unsafe {
    [
        {
            let mut init = NsInfo {
                name: b"cgroup\0" as *const u8 as *const libc::c_char,
                do_unshare: &opt_unshare_cgroup as *const bool as *mut bool,
                id: 0 as libc::c_int as ino_t,
            };
            init
        },
        {
            let mut init = NsInfo {
                name: b"ipc\0" as *const u8 as *const libc::c_char,
                do_unshare: &opt_unshare_ipc as *const bool as *mut bool,
                id: 0 as libc::c_int as ino_t,
            };
            init
        },
        {
            let mut init = NsInfo {
                name: b"mnt\0" as *const u8 as *const libc::c_char,
                do_unshare: std::ptr::null_mut() as *mut bool,
                id: 0 as libc::c_int as ino_t,
            };
            init
        },
        {
            let mut init = NsInfo {
                name: b"net\0" as *const u8 as *const libc::c_char,
                do_unshare: &opt_unshare_net as *const bool as *mut bool,
                id: 0 as libc::c_int as ino_t,
            };
            init
        },
        {
            let mut init = NsInfo {
                name: b"pid\0" as *const u8 as *const libc::c_char,
                do_unshare: &opt_unshare_pid as *const bool as *mut bool,
                id: 0 as libc::c_int as ino_t,
            };
            init
        },
        {
            let mut init = NsInfo {
                name: b"uts\0" as *const u8 as *const libc::c_char,
                do_unshare: &opt_unshare_uts as *const bool as *mut bool,
                id: 0 as libc::c_int as ino_t,
            };
            init
        },
        {
            let mut init = NsInfo {
                name: std::ptr::null_mut() as *const libc::c_char,
                do_unshare: std::ptr::null_mut() as *mut bool,
                id: 0 as libc::c_int as ino_t,
            };
            init
        },
    ]
};

static mut ops: *mut SetupOp = std::ptr::null_mut() as *mut SetupOp;
#[inline]

unsafe fn _op_append_new() -> *mut SetupOp {
    let mut self_0 = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<SetupOp>(),
    ) as *mut SetupOp;
    if !last_op.is_null() {
        (*last_op).next = self_0;
    } else {
        ops = self_0;
    }
    last_op = self_0;
    return self_0;
}

static mut last_op: *mut SetupOp = std::ptr::null_mut() as *mut SetupOp;

unsafe fn setup_op_new(mut type_0: SetupOpType) -> *mut SetupOp {
    let mut op = _op_append_new();
    (*op).type_0 = type_0;
    (*op).fd = -(1 as libc::c_int);
    (*op).flags = 0 as SetupOpFlag;
    return op;
}

static mut lock_files: *mut LockFile = std::ptr::null_mut() as *mut LockFile;

static mut last_lock_file: *mut LockFile = std::ptr::null_mut() as *mut LockFile;
#[inline]

unsafe fn _lock_file_append_new() -> *mut LockFile {
    let mut self_0 = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<LockFile>(),
    ) as *mut LockFile;
    if !last_lock_file.is_null() {
        (*last_lock_file).next = self_0;
    } else {
        lock_files = self_0;
    }
    last_lock_file = self_0;
    return self_0;
}

unsafe fn lock_file_new(mut path: *const libc::c_char) -> *mut LockFile {
    let mut lock = _lock_file_append_new();
    (*lock).path = path;
    return lock;
}
#[inline]

unsafe fn _seccomp_program_append_new() -> *mut SeccompProgram {
    let mut self_0 = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<SeccompProgram>(),
    ) as *mut SeccompProgram;
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

unsafe fn seccomp_program_new(mut fd: *mut libc::c_int) -> *mut SeccompProgram {
    let mut self_0 = _seccomp_program_append_new();
    let mut data = std::ptr::null_mut() as *mut libc::c_char;
    let mut len: size_t = 0;
    data = load_file_data(*fd, &mut len);
    if data.is_null() {
        die_with_error!(b"Can't read seccomp data\0" as *const u8 as *const libc::c_char);
    }
    close(*fd);
    *fd = -(1 as libc::c_int);
    if len.wrapping_rem(8) != 0 {
        die!(b"Invalid seccomp data, must be multiple of 8\0" as *const u8 as *const libc::c_char);
    }
    (*self_0).program.len = len.wrapping_div(8) as _;
    (*self_0).program.filter = (if 0 as libc::c_int != 0 {
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
        ) != 0 as libc::c_int
        {
            if errno!() == EINVAL {
                die!(
                    b"Unable to set up system call filtering as requested: prctl(PR_SET_SECCOMP) reported EINVAL. (Hint: this requires a kernel configured with CONFIG_SECCOMP and CONFIG_SECCOMP_FILTER.)\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            die_with_error!(b"prctl(PR_SET_SECCOMP)\0" as *const u8 as *const libc::c_char);
        }
        program = (*program).next;
    }
}

unsafe fn usage(mut ecode: libc::c_int, mut out: *mut FILE) {
    fprintf(
        out,
        b"usage: %s [OPTIONS...] [--] COMMAND [ARGS...]\n\n\0" as *const u8 as *const libc::c_char,
        if !argv0.is_null() {
            argv0
        } else {
            b"bwrap\0" as *const u8 as *const libc::c_char
        },
    );
    fprintf(
        out,
        b"    --help                       Print this help\n    --version                    Print version\n    --args FD                    Parse NUL-separated args from FD\n    --argv0 VALUE                Set argv[0] to the value VALUE before running the program\n    --level-prefix               Prepend e.g. <3> to diagnostic messages\n    --unshare-all                Unshare every namespace we support by default\n    --share-net                  Retain the network namespace (can only combine with --unshare-all)\n    --unshare-user               Create new user namespace (may be automatically implied if not setuid)\n    --unshare-user-try           Create new user namespace if possible else continue by skipping it\n    --unshare-ipc                Create new ipc namespace\n    --unshare-pid                Create new pid namespace\n    --unshare-net                Create new network namespace\n    --unshare-uts                Create new uts namespace\n    --unshare-cgroup             Create new cgroup namespace\n    --unshare-cgroup-try         Create new cgroup namespace if possible else continue by skipping it\n    --userns FD                  Use this user namespace (cannot combine with --unshare-user)\n    --userns2 FD                 After setup switch to this user namespace, only useful with --userns\n    --disable-userns             Disable further use of user namespaces inside sandbox\n    --assert-userns-disabled     Fail unless further use of user namespace inside sandbox is disabled\n    --pidns FD                   Use this pid namespace (as parent namespace if using --unshare-pid)\n    --uid UID                    Custom uid in the sandbox (requires --unshare-user or --userns)\n    --gid GID                    Custom gid in the sandbox (requires --unshare-user or --userns)\n    --hostname NAME              Custom hostname in the sandbox (requires --unshare-uts)\n    --chdir DIR                  Change directory to DIR\n    --clearenv                   Unset all environment variables\n    --setenv VAR VALUE           Set an environment variable\n    --unsetenv VAR               Unset an environment variable\n    --lock-file DEST             Take a lock on DEST while sandbox is running\n    --sync-fd FD                 Keep this fd open while sandbox is running\n    --bind SRC DEST              Bind mount the host path SRC on DEST\n    --bind-try SRC DEST          Equal to --bind but ignores non-existent SRC\n    --dev-bind SRC DEST          Bind mount the host path SRC on DEST, allowing device access\n    --dev-bind-try SRC DEST      Equal to --dev-bind but ignores non-existent SRC\n    --ro-bind SRC DEST           Bind mount the host path SRC readonly on DEST\n    --ro-bind-try SRC DEST       Equal to --ro-bind but ignores non-existent SRC\n    --bind-fd FD DEST            Bind open directory or path fd on DEST\n    --ro-bind-fd FD DEST         Bind open directory or path fd read-only on DEST\n    --remount-ro DEST            Remount DEST as readonly; does not recursively remount\n    --overlay-src SRC            Read files from SRC in the following overlay\n    --overlay RWSRC WORKDIR DEST Mount overlayfs on DEST, with RWSRC as the host path for writes and\n                                 WORKDIR an empty directory on the same filesystem as RWSRC\n    --tmp-overlay DEST           Mount overlayfs on DEST, with writes going to an invisible tmpfs\n    --ro-overlay DEST            Mount overlayfs read-only on DEST\n    --exec-label LABEL           Exec label for the sandbox\n    --file-label LABEL           File label for temporary sandbox content\n    --proc DEST                  Mount new procfs on DEST\n    --dev DEST                   Mount new dev on DEST\n    --tmpfs DEST                 Mount new tmpfs on DEST\n    --mqueue DEST                Mount new mqueue on DEST\n    --dir DEST                   Create dir at DEST\n    --file FD DEST               Copy from FD to destination DEST\n    --bind-data FD DEST          Copy from FD to file which is bind-mounted on DEST\n    --ro-bind-data FD DEST       Copy from FD to file which is readonly bind-mounted on DEST\n    --symlink SRC DEST           Create symlink at DEST with target SRC\n    --seccomp FD                 Load and use seccomp rules from FD (not repeatable)\n    --add-seccomp-fd FD          Load and use seccomp rules from FD (repeatable)\n    --block-fd FD                Block on FD until some data to read is available\n    --userns-block-fd FD         Block on FD until the user namespace is ready\n    --info-fd FD                 Write information about the running container to FD\n    --json-status-fd FD          Write container status to FD as multiple JSON documents\n    --new-session                Create a new terminal session\n    --die-with-parent            Kills with SIGKILL child process (COMMAND) when bwrap or bwrap's parent dies.\n    --as-pid-1                   Do not install a reaper process with PID=1\n    --cap-add CAP                Add cap CAP when running as privileged user\n    --cap-drop CAP               Drop cap CAP when running as privileged user\n    --perms OCTAL                Set permissions of next argument (--bind-data, --file, etc.)\n    --size BYTES                 Set size of next argument (only for --tmpfs)\n    --chmod OCTAL PATH           Change permissions of PATH (must already exist)\n\0"
            as *const u8 as *const libc::c_char,
    );
    exit(ecode);
}

unsafe fn handle_die_with_parent() {
    if opt_die_with_parent as libc::c_int != 0
        && prctl(
            PR_SET_PDEATHSIG,
            SIGKILL,
            0 as libc::c_int,
            0 as libc::c_int,
            0 as libc::c_int,
        ) != 0 as libc::c_int
    {
        die_with_error!(b"prctl\0" as *const u8 as *const libc::c_char);
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
    ) == -(1 as libc::c_int)
    {
        die_with_error!(b"sigprocmask\0" as *const u8 as *const libc::c_char);
    }
    while waitpid(-(1 as libc::c_int), &mut status, WNOHANG) > 0 as libc::c_int {}
}

unsafe fn unblock_sigchild() {
    let mut mask = std::mem::zeroed();
    sigemptyset(&mut mask);
    sigaddset(&mut mask, libc::SIGCHLD);
    if sigprocmask(
        libc::SIG_UNBLOCK,
        &mut mask,
        std::ptr::null_mut() as *mut sigset_t,
    ) == -(1 as libc::c_int)
    {
        die_with_error!(b"sigprocmask\0" as *const u8 as *const libc::c_char);
    }
}

unsafe fn close_extra_fds(mut data: *mut libc::c_void, mut fd: libc::c_int) -> libc::c_int {
    let mut extra_fds = data as *mut libc::c_int;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while *extra_fds.offset(i as isize) != -(1 as libc::c_int) {
        if fd == *extra_fds.offset(i as isize) {
            return 0 as libc::c_int;
        }
        i += 1;
    }
    if fd <= 2 as libc::c_int {
        return 0 as libc::c_int;
    }
    close(fd);
    return 0 as libc::c_int;
}

unsafe fn propagate_exit_status(mut status: libc::c_int) -> libc::c_int {
    if status & 0x7f as libc::c_int == 0 as libc::c_int {
        return (status & 0xff00 as libc::c_int) >> 8 as libc::c_int;
    }
    if ((status & 0x7f as libc::c_int) + 1 as libc::c_int) as libc::c_schar as libc::c_int
        >> 1 as libc::c_int
        > 0 as libc::c_int
    {
        return 128 as libc::c_int + (status & 0x7f as libc::c_int);
    }
    return 255 as libc::c_int;
}

unsafe fn dump_info(mut fd: libc::c_int, mut output: *const libc::c_char, mut exit_on_error: bool) {
    let mut len = strlen(output);
    if write_to_fd(fd, output, len as ssize_t) != 0 && exit_on_error {
        die_with_error!(b"Write to info_fd\0" as *const u8 as *const libc::c_char);
    }
}

unsafe fn report_child_exit_status(mut exitc: libc::c_int, mut setup_finished_fd: libc::c_int) {
    let mut s: ssize_t = 0;
    let mut data: [libc::c_char; 2] = [0; 2];
    let mut output = std::ptr::null_mut() as *mut libc::c_char;
    if opt_json_status_fd == -(1 as libc::c_int) || setup_finished_fd == -(1 as libc::c_int) {
        return;
    }
    s = loop {
        let __result = read(
            setup_finished_fd,
            data.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[libc::c_char; 2]>(),
        );
        if !(__result == -(1) && errno!() == EINTR) {
            break __result;
        }
    };
    if s == -(1) && errno!() != libc::EAGAIN {
        die_with_error!(b"read eventfd\0" as *const u8 as *const libc::c_char);
    }
    if s != 1 {
        return;
    }
    output = xasprintf(
        b"{ \"exit-code\": %i }\n\0" as *const u8 as *const libc::c_char,
        exitc,
    );
    dump_info(opt_json_status_fd, output, false);
    close(opt_json_status_fd);
    opt_json_status_fd = -(1 as libc::c_int);
    close(setup_finished_fd);
}

unsafe fn monitor_child(
    mut event_fd: libc::c_int,
    mut child_pid: pid_t,
    mut setup_finished_fd: libc::c_int,
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
    let mut dont_close: [libc::c_int; 4] = [
        -(1 as libc::c_int),
        -(1 as libc::c_int),
        -(1 as libc::c_int),
        -(1 as libc::c_int),
    ];
    let mut j = 0 as libc::c_int as libc::c_uint;
    let mut exitc: libc::c_int = 0;
    let mut died_pid: pid_t = 0;
    let mut died_status: libc::c_int = 0;
    if event_fd != -(1 as libc::c_int) {
        let fresh0 = j;
        j = j.wrapping_add(1);
        dont_close[fresh0 as usize] = event_fd;
    }
    if opt_json_status_fd != -(1 as libc::c_int) {
        let fresh1 = j;
        j = j.wrapping_add(1);
        dont_close[fresh1 as usize] = opt_json_status_fd;
    }
    if setup_finished_fd != -(1 as libc::c_int) {
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
    signal_fd = signalfd(
        -(1 as libc::c_int),
        &mut mask,
        libc::SFD_CLOEXEC | libc::SFD_NONBLOCK,
    );
    if signal_fd == -(1 as libc::c_int) {
        die_with_error!(b"Can't create signalfd\0" as *const u8 as *const libc::c_char);
    }
    num_fds = 1 as libc::c_int;
    fds[0 as libc::c_int as usize].fd = signal_fd;
    fds[0 as libc::c_int as usize].events = POLLIN as libc::c_short;
    if event_fd != -(1 as libc::c_int) {
        fds[1 as libc::c_int as usize].fd = event_fd;
        fds[1 as libc::c_int as usize].events = POLLIN as libc::c_short;
        num_fds += 1;
    }
    loop {
        fds[1 as libc::c_int as usize].revents = 0 as libc::c_int as libc::c_short;
        fds[0 as libc::c_int as usize].revents = fds[1 as libc::c_int as usize].revents;
        res = poll(fds.as_mut_ptr(), num_fds as nfds_t, -(1 as libc::c_int));
        if res == -(1 as libc::c_int) && errno!() != EINTR {
            die_with_error!(b"poll\0" as *const u8 as *const libc::c_char);
        }
        if event_fd != -(1 as libc::c_int) {
            s = read(
                event_fd,
                &mut val as *mut u64 as *mut libc::c_void,
                8 as libc::c_int as size_t,
            );
            if s == -1 && errno!() != libc::EINTR && errno!() != libc::EAGAIN {
                die_with_error!(b"read eventfd\0" as *const u8 as *const libc::c_char);
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
            die_with_error!(b"read signalfd\0" as *const u8 as *const libc::c_char);
        }
        loop {
            died_pid = waitpid(-(1 as libc::c_int), &mut died_status, libc::WNOHANG);
            if !(died_pid > 0 as libc::c_int) {
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

unsafe fn do_init(mut event_fd: libc::c_int, mut initial_pid: pid_t) -> libc::c_int {
    let mut initial_exit_status = 1 as libc::c_int;
    let mut lock = 0 as *mut LockFile;
    lock = lock_files;
    while !lock.is_null() {
        let mut fd = ({
            let mut __result: libc::c_long = 0;
            loop {
                __result =
                    open((*lock).path, 0 as libc::c_int | 0o2000000 as libc::c_int) as libc::c_long;
                if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                    break;
                }
            }
            __result
        }) as libc::c_int;
        if fd == -(1 as libc::c_int) {
            die_with_error!(
                b"Unable to open lock file %s\0" as *const u8 as *const libc::c_char,
                (*lock).path,
            );
        }
        let mut l = {
            let mut init = flock {
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
                if !(__result == -(1) && errno!() == EINTR) {
                    break;
                }
            }
            __result
        }) < 0 as libc::c_int as libc::c_long
        {
            die_with_error!(
                b"Unable to lock file %s\0" as *const u8 as *const libc::c_char,
                (*lock).path,
            );
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
                if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                    break;
                }
            }
            __result
        }) as pid_t;
        if child == initial_pid {
            initial_exit_status = propagate_exit_status(status);
            if event_fd != -(1 as libc::c_int) {
                let mut val = (initial_exit_status + 1 as libc::c_int) as u64;
                let _res: isize = {
                    loop {
                        let __result = write(
                            event_fd,
                            &raw mut val as *const libc::c_void,
                            8 as libc::c_int as size_t,
                        );
                        if !(__result == -(1) && errno!() == EINTR) {
                            break __result as _;
                        }
                    }
                };
            }
        }
        if !(child == -(1 as libc::c_int) && errno!() != EINTR) {
            continue;
        }
        if errno!() != ECHILD {
            die_with_error!(b"init wait()\0" as *const u8 as *const libc::c_char);
        }
        break;
    }
    lock = lock_files;
    while !lock.is_null() {
        if (*lock).fd >= 0 as libc::c_int {
            close((*lock).fd);
            (*lock).fd = -(1 as libc::c_int);
        }
        lock = (*lock).next;
    }
    return initial_exit_status;
}

static mut opt_cap_add_or_drop_used: bool = false;

static mut requested_caps: [u32; 2] = [0 as libc::c_int as u32, 0 as libc::c_int as u32];

pub const REQUIRED_CAPS_0: libc::c_long = (1 as libc::c_long)
    << (21 as libc::c_int & 31 as libc::c_int)
    | (1 as libc::c_long) << (18 as libc::c_int & 31 as libc::c_int)
    | (1 as libc::c_long) << (12 as libc::c_int & 31 as libc::c_int)
    | (1 as libc::c_long) << (7 as libc::c_int & 31 as libc::c_int)
    | (1 as libc::c_long) << (6 as libc::c_int & 31 as libc::c_int)
    | (1 as libc::c_long) << (19 as libc::c_int & 31 as libc::c_int);

pub const REQUIRED_CAPS_1: libc::c_int = 0 as libc::c_int;

unsafe fn set_required_caps() {
    let mut hdr = {
        let mut init = __user_cap_header_struct {
            version: _LINUX_CAPABILITY_VERSION_3 as u32,
            pid: 0 as libc::c_int,
        };
        init
    };
    let mut data: [__user_cap_data_struct; 2] = [
        {
            let mut init = __user_cap_data_struct {
                effective: 0 as libc::c_int as u32,
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
    data[0 as libc::c_int as usize].effective = REQUIRED_CAPS_0 as u32;
    data[0 as libc::c_int as usize].permitted = REQUIRED_CAPS_0 as u32;
    data[0 as libc::c_int as usize].inheritable = 0 as libc::c_int as u32;
    data[1 as libc::c_int as usize].effective = REQUIRED_CAPS_1 as u32;
    data[1 as libc::c_int as usize].permitted = REQUIRED_CAPS_1 as u32;
    data[1 as libc::c_int as usize].inheritable = 0 as libc::c_int as u32;
    if capset(&mut hdr, data.as_mut_ptr()) < 0 as libc::c_int {
        die_with_error!(b"capset failed\0" as *const u8 as *const libc::c_char);
    }
}

unsafe fn drop_all_caps(mut keep_requested_caps: bool) {
    let mut hdr = {
        let mut init = __user_cap_header_struct {
            version: _LINUX_CAPABILITY_VERSION_3 as u32,
            pid: 0 as libc::c_int,
        };
        init
    };
    let mut data: [__user_cap_data_struct; 2] = [
        {
            let mut init = __user_cap_data_struct {
                effective: 0 as libc::c_int as u32,
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
        if !opt_cap_add_or_drop_used && real_uid == 0 as libc::c_int as libc::c_uint {
            assert!(!is_privileged);
            return;
        }
        data[0 as libc::c_int as usize].effective = requested_caps[0 as libc::c_int as usize];
        data[0 as libc::c_int as usize].permitted = requested_caps[0 as libc::c_int as usize];
        data[0 as libc::c_int as usize].inheritable = requested_caps[0 as libc::c_int as usize];
        data[1 as libc::c_int as usize].effective = requested_caps[1 as libc::c_int as usize];
        data[1 as libc::c_int as usize].permitted = requested_caps[1 as libc::c_int as usize];
        data[1 as libc::c_int as usize].inheritable = requested_caps[1 as libc::c_int as usize];
    }
    if capset(&mut hdr, data.as_mut_ptr()) < 0 as libc::c_int {
        if errno!() == EPERM && real_uid == 0 as libc::c_int as libc::c_uint && !is_privileged {
            return;
        } else {
            die_with_error!(b"capset failed\0" as *const u8 as *const libc::c_char);
        }
    }
}

unsafe fn has_caps() -> bool {
    let mut hdr = {
        let mut init = __user_cap_header_struct {
            version: _LINUX_CAPABILITY_VERSION_3 as u32,
            pid: 0 as libc::c_int,
        };
        init
    };
    let mut data: [__user_cap_data_struct; 2] = [
        {
            let mut init = __user_cap_data_struct {
                effective: 0 as libc::c_int as u32,
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
    if capget(&mut hdr, data.as_mut_ptr()) < 0 as libc::c_int {
        die_with_error!(b"capget failed\0" as *const u8 as *const libc::c_char);
    }
    return data[0 as libc::c_int as usize].permitted != 0 as libc::c_int as libc::c_uint
        || data[1 as libc::c_int as usize].permitted != 0 as libc::c_int as libc::c_uint;
}

unsafe fn prctl_caps(mut caps: *mut u32, mut do_cap_bounding: bool, mut do_set_ambient: bool) {
    let mut cap: libc::c_ulong = 0;
    cap = 0 as libc::c_int as libc::c_ulong;
    while cap <= CAP_LAST_CAP as libc::c_ulong {
        let mut keep = false;
        if cap < 32 as libc::c_int as libc::c_ulong {
            if (1 as libc::c_long) << (cap & 31 as libc::c_int as libc::c_ulong)
                & *caps.offset(0 as libc::c_int as isize) as libc::c_long
                != 0
            {
                keep = true;
            }
        } else if (1 as libc::c_long)
            << (cap.wrapping_sub(32 as libc::c_int as libc::c_ulong)
                & 31 as libc::c_int as libc::c_ulong)
            & *caps.offset(1 as libc::c_int as isize) as libc::c_long
            != 0
        {
            keep = true;
        }
        if keep as libc::c_int != 0 && do_set_ambient as libc::c_int != 0 {
            let mut res = prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                cap,
                0 as libc::c_int,
                0 as libc::c_int,
            );
            if res == -(1 as libc::c_int) && !(errno!() == EINVAL || errno!() == EPERM) {
                die_with_error!(
                    b"Adding ambient capability %ld\0" as *const u8 as *const libc::c_char,
                    cap,
                );
            }
        }
        if !keep && do_cap_bounding as libc::c_int != 0 {
            let mut res_0 = prctl(
                PR_CAPBSET_DROP,
                cap,
                0 as libc::c_int,
                0 as libc::c_int,
                0 as libc::c_int,
            );
            if res_0 == -(1 as libc::c_int) && !(errno!() == EINVAL || errno!() == EPERM) {
                die_with_error!(
                    b"Dropping capability %ld from bounds\0" as *const u8 as *const libc::c_char,
                    cap,
                );
            }
        }
        cap = cap.wrapping_add(1);
    }
}

unsafe fn drop_cap_bounding_set(mut drop_all: bool) {
    if !drop_all {
        prctl_caps(requested_caps.as_mut_ptr(), true, false);
    } else {
        let mut no_caps: [u32; 2] = [0 as libc::c_int as u32, 0 as libc::c_int as u32];
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
        if euid != 0 as libc::c_int as libc::c_uint {
            die!(
                b"Unexpected setuid user %d, should be 0\0" as *const u8 as *const libc::c_char,
                euid,
            );
        }
        is_privileged = true;
        if setfsuid(real_uid) < 0 as libc::c_int {
            die_with_error!(b"Unable to set fsuid\0" as *const u8 as *const libc::c_char);
        }
        new_fsuid = setfsuid(-(1 as libc::c_int) as uid_t) as uid_t;
        if new_fsuid != real_uid {
            die!(
                b"Unable to set fsuid (was %d)\0" as *const u8 as *const libc::c_char,
                new_fsuid as libc::c_int,
            );
        }
        drop_cap_bounding_set(true);
        set_required_caps();
    } else if real_uid != 0 as libc::c_int as libc::c_uint && has_caps() as libc::c_int != 0 {
        die!(
            b"Unexpected capabilities but not setuid, old file caps config?\0" as *const u8
                as *const libc::c_char,
        );
    } else if real_uid == 0 as libc::c_int as libc::c_uint {
        let mut hdr = {
            let mut init = __user_cap_header_struct {
                version: _LINUX_CAPABILITY_VERSION_3 as u32,
                pid: 0 as libc::c_int,
            };
            init
        };
        let mut data: [__user_cap_data_struct; 2] = [
            {
                let mut init = __user_cap_data_struct {
                    effective: 0 as libc::c_int as u32,
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
        if capget(&mut hdr, data.as_mut_ptr()) < 0 as libc::c_int {
            die_with_error!(b"capget (for uid == 0) failed\0" as *const u8 as *const libc::c_char);
        }
        requested_caps[0 as libc::c_int as usize] = data[0 as libc::c_int as usize].effective;
        requested_caps[1 as libc::c_int as usize] = data[1 as libc::c_int as usize].effective;
    }
}

unsafe fn switch_to_user_with_privs() {
    if opt_unshare_user as libc::c_int != 0 || opt_userns_fd != -(1 as libc::c_int) {
        drop_cap_bounding_set(false);
    }
    if opt_userns_fd != -(1 as libc::c_int) {
        if opt_sandbox_uid != real_uid && setuid(opt_sandbox_uid) < 0 as libc::c_int {
            die_with_error!(
                b"unable to switch to uid %d\0" as *const u8 as *const libc::c_char,
                opt_sandbox_uid,
            );
        }
        if opt_sandbox_gid != real_gid && setgid(opt_sandbox_gid) < 0 as libc::c_int {
            die_with_error!(
                b"unable to switch to gid %d\0" as *const u8 as *const libc::c_char,
                opt_sandbox_gid,
            );
        }
    }
    if !is_privileged {
        return;
    }
    if prctl(
        PR_SET_KEEPCAPS,
        1 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
    ) < 0 as libc::c_int
    {
        die_with_error!(b"prctl(PR_SET_KEEPCAPS) failed\0" as *const u8 as *const libc::c_char);
    }
    if setuid(opt_sandbox_uid) < 0 as libc::c_int {
        die_with_error!(b"unable to drop root uid\0" as *const u8 as *const libc::c_char);
    }
    set_required_caps();
}

unsafe fn drop_privs(mut keep_requested_caps: bool, mut already_changed_uid: bool) {
    assert!(!keep_requested_caps || !is_privileged);
    if is_privileged as libc::c_int != 0
        && !already_changed_uid
        && setuid(opt_sandbox_uid) < 0 as libc::c_int
    {
        die_with_error!(b"unable to drop root uid\0" as *const u8 as *const libc::c_char);
    }
    drop_all_caps(keep_requested_caps);
    if prctl(
        PR_SET_DUMPABLE,
        1 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
    ) != 0 as libc::c_int
    {
        die_with_error!(b"can't set dumpable\0" as *const u8 as *const libc::c_char);
    }
}

unsafe fn write_uid_gid_map(
    mut sandbox_uid: uid_t,
    mut parent_uid: uid_t,
    mut sandbox_gid: uid_t,
    mut parent_gid: uid_t,
    mut pid: pid_t,
    mut deny_groups: bool,
    mut map_root: bool,
) {
    let mut uid_map = std::ptr::null_mut() as *mut libc::c_char;
    let mut gid_map = std::ptr::null_mut() as *mut libc::c_char;
    let mut dir = std::ptr::null_mut() as *mut libc::c_char;
    let mut dir_fd = -(1 as libc::c_int);
    let mut old_fsuid = -(1 as libc::c_int) as uid_t;
    if pid == -(1 as libc::c_int) {
        dir = xstrdup(b"self\0" as *const u8 as *const libc::c_char);
    } else {
        dir = xasprintf(b"%d\0" as *const u8 as *const libc::c_char, pid);
    }
    dir_fd = openat(proc_fd, dir, O_PATH);
    if dir_fd < 0 as libc::c_int {
        die_with_error!(
            b"open /proc/%s failed\0" as *const u8 as *const libc::c_char,
            dir,
        );
    }
    if map_root as libc::c_int != 0
        && parent_uid != 0 as libc::c_int as libc::c_uint
        && sandbox_uid != 0 as libc::c_int as libc::c_uint
    {
        uid_map = xasprintf(
            b"0 %d 1\n%d %d 1\n\0" as *const u8 as *const libc::c_char,
            overflow_uid,
            sandbox_uid,
            parent_uid,
        );
    } else {
        uid_map = xasprintf(
            b"%d %d 1\n\0" as *const u8 as *const libc::c_char,
            sandbox_uid,
            parent_uid,
        );
    }
    if map_root as libc::c_int != 0
        && parent_gid != 0 as libc::c_int as libc::c_uint
        && sandbox_gid != 0 as libc::c_int as libc::c_uint
    {
        gid_map = xasprintf(
            b"0 %d 1\n%d %d 1\n\0" as *const u8 as *const libc::c_char,
            overflow_gid,
            sandbox_gid,
            parent_gid,
        );
    } else {
        gid_map = xasprintf(
            b"%d %d 1\n\0" as *const u8 as *const libc::c_char,
            sandbox_gid,
            parent_gid,
        );
    }
    if is_privileged {
        old_fsuid = setfsuid(0 as libc::c_int as uid_t) as uid_t;
    }
    if write_file_at(
        dir_fd,
        b"uid_map\0" as *const u8 as *const libc::c_char,
        uid_map,
    ) != 0 as libc::c_int
    {
        die_with_error!(b"setting up uid map\0" as *const u8 as *const libc::c_char);
    }
    if deny_groups as libc::c_int != 0
        && write_file_at(
            dir_fd,
            b"setgroups\0" as *const u8 as *const libc::c_char,
            b"deny\n\0" as *const u8 as *const libc::c_char,
        ) != 0 as libc::c_int
    {
        if errno!() != ENOENT {
            die_with_error!(b"error writing to setgroups\0" as *const u8 as *const libc::c_char);
        }
    }
    if write_file_at(
        dir_fd,
        b"gid_map\0" as *const u8 as *const libc::c_char,
        gid_map,
    ) != 0 as libc::c_int
    {
        die_with_error!(b"setting up gid map\0" as *const u8 as *const libc::c_char);
    }
    if is_privileged {
        setfsuid(old_fsuid);
        if setfsuid(-(1 as libc::c_int) as uid_t) as uid_t != real_uid {
            die!(b"Unable to re-set fsuid\0" as *const u8 as *const libc::c_char);
        }
    }
}

unsafe fn privileged_op(
    mut privileged_op_socket: libc::c_int,
    mut op: u32,
    mut flags: u32,
    mut perms: u32,
    mut size_arg: size_t,
    mut arg1: *const libc::c_char,
    mut arg2: *const libc::c_char,
) {
    let mut bind_result = BIND_MOUNT_SUCCESS;
    let mut failing_path = std::ptr::null_mut() as *mut libc::c_char;
    if privileged_op_socket != -(1 as libc::c_int) {
        let mut buffer: [u32; 2048] = [0; 2048];
        let mut op_buffer = buffer.as_mut_ptr() as *mut PrivSepOp;
        let mut buffer_size = ::core::mem::size_of::<PrivSepOp>();
        let mut arg1_offset = 0 as libc::c_int as u32;
        let mut arg2_offset = 0 as libc::c_int as u32;
        if !arg1.is_null() {
            arg1_offset = buffer_size as u32;
            buffer_size = (buffer_size).wrapping_add((strlen(arg1) as size_t).wrapping_add(1));
        }
        if !arg2.is_null() {
            arg2_offset = buffer_size as u32;
            buffer_size = (buffer_size).wrapping_add((strlen(arg2)).wrapping_add(1)) as size_t;
        }
        if buffer_size >= ::core::mem::size_of::<[u32; 2048]>() {
            die!(b"privilege separation operation to large\0" as *const u8 as *const libc::c_char);
        }
        (*op_buffer).op = op;
        (*op_buffer).flags = flags;
        (*op_buffer).perms = perms;
        (*op_buffer).size_arg = size_arg;
        (*op_buffer).arg1_offset = arg1_offset;
        (*op_buffer).arg2_offset = arg2_offset;
        if !arg1.is_null() {
            strcpy(
                (buffer.as_mut_ptr() as *mut libc::c_char).offset(arg1_offset as isize),
                arg1,
            );
        }
        if !arg2.is_null() {
            strcpy(
                (buffer.as_mut_ptr() as *mut libc::c_char).offset(arg2_offset as isize),
                arg2,
            );
        }
        if ({
            let mut __result = 0;
            loop {
                __result = write(
                    privileged_op_socket,
                    buffer.as_mut_ptr() as *const libc::c_void,
                    buffer_size,
                );
                if !(__result == -(1) && errno!() == EINTR) {
                    break;
                }
            }
            __result
        }) != buffer_size as ssize_t
        {
            die!(b"Can't write to privileged_op_socket\0" as *const u8 as *const libc::c_char);
        }
        if ({
            let mut __result = 0;
            loop {
                __result = read(
                    privileged_op_socket,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    1 as libc::c_int as size_t,
                );
                if !(__result == -(1) && errno!() == EINTR) {
                    break;
                }
            }
            __result
        }) != 1
        {
            die!(b"Can't read from privileged_op_socket\0" as *const u8 as *const libc::c_char);
        }
        return;
    }
    match op {
        0 => {}
        7 => {
            bind_result = bind_mount(
                proc_fd,
                std::ptr::null_mut() as *const libc::c_char,
                arg2,
                BIND_READONLY,
                &mut failing_path,
            );
            if bind_result as libc::c_uint != BIND_MOUNT_SUCCESS as libc::c_int as libc::c_uint {
                die_with_bind_result!(
                    bind_result,
                    errno!(),
                    failing_path,
                    b"Can't remount readonly on %s\0" as *const u8 as *const libc::c_char,
                    arg2,
                );
            }
            assert!(failing_path.is_null());
        }
        1 => {
            bind_result = bind_mount(
                proc_fd,
                arg1,
                arg2,
                (BIND_RECURSIVE as libc::c_int as libc::c_uint | flags) as bind_option_t,
                &mut failing_path,
            );
            if bind_result as libc::c_uint != BIND_MOUNT_SUCCESS as libc::c_int as libc::c_uint {
                die_with_bind_result!(
                    bind_result,
                    errno!(),
                    failing_path,
                    b"Can't bind mount %s on %s\0" as *const u8 as *const libc::c_char,
                    arg1,
                    arg2,
                );
            }
            assert!(failing_path.is_null());
        }
        3 => {
            if mount(
                b"proc\0" as *const u8 as *const libc::c_char,
                arg1,
                b"proc\0" as *const u8 as *const libc::c_char,
                (MS_NOSUID | MS_NOEXEC | MS_NODEV) as libc::c_ulong,
                std::ptr::null_mut() as *const libc::c_void,
            ) != 0 as libc::c_int
            {
                die_with_mount_error!(
                    b"Can't mount proc on %s\0" as *const u8 as *const libc::c_char,
                    arg1,
                );
            }
        }
        4 => {
            let mut mode = std::ptr::null_mut() as *mut libc::c_char;
            if size_arg > MAX_TMPFS_BYTES as size_t {
                die_with_error!(
                    b"Specified tmpfs size too large (%zu > %zu)\0" as *const u8
                        as *const libc::c_char,
                    size_arg,
                    MAX_TMPFS_BYTES,
                );
            }
            if size_arg != 0 {
                mode = xasprintf(
                    b"mode=%#o,size=%zu\0" as *const u8 as *const libc::c_char,
                    perms,
                    size_arg,
                );
            } else {
                mode = xasprintf(b"mode=%#o\0" as *const u8 as *const libc::c_char, perms);
            }
            let mut opt = label_mount(mode, opt_file_label);
            if mount(
                b"tmpfs\0" as *const u8 as *const libc::c_char,
                arg1,
                b"tmpfs\0" as *const u8 as *const libc::c_char,
                (MS_NOSUID | MS_NODEV) as libc::c_ulong,
                opt as *const libc::c_void,
            ) != 0 as libc::c_int
            {
                die_with_mount_error!(
                    b"Can't mount tmpfs on %s\0" as *const u8 as *const libc::c_char,
                    arg1,
                );
            }
        }
        5 => {
            if mount(
                b"devpts\0" as *const u8 as *const libc::c_char,
                arg1,
                b"devpts\0" as *const u8 as *const libc::c_char,
                (MS_NOSUID | MS_NOEXEC) as libc::c_ulong,
                b"newinstance,ptmxmode=0666,mode=620\0" as *const u8 as *const libc::c_char
                    as *const libc::c_void,
            ) != 0 as libc::c_int
            {
                die_with_mount_error!(
                    b"Can't mount devpts on %s\0" as *const u8 as *const libc::c_char,
                    arg1,
                );
            }
        }
        6 => {
            if mount(
                b"mqueue\0" as *const u8 as *const libc::c_char,
                arg1,
                b"mqueue\0" as *const u8 as *const libc::c_char,
                0 as libc::c_int as libc::c_ulong,
                std::ptr::null_mut() as *const libc::c_void,
            ) != 0 as libc::c_int
            {
                die_with_mount_error!(
                    b"Can't mount mqueue on %s\0" as *const u8 as *const libc::c_char,
                    arg1,
                );
            }
        }
        2 => {
            if mount(
                b"overlay\0" as *const u8 as *const libc::c_char,
                arg2,
                b"overlay\0" as *const u8 as *const libc::c_char,
                MS_MGC_VAL as libc::c_ulong,
                arg1 as *const libc::c_void,
            ) != 0 as libc::c_int
            {
                if errno!() == ELOOP {
                    die!(
                        b"Can't make overlay mount on %s with options %s: Overlay directories may not overlap\0"
                            as *const u8 as *const libc::c_char,
                        arg2,
                        arg1,
                    );
                }
                die_with_mount_error!(
                    b"Can't make overlay mount on %s with options %s\0" as *const u8
                        as *const libc::c_char,
                    arg2,
                    arg1,
                );
            }
        }
        8 => {
            if !opt_unshare_uts {
                die!(
                    b"Refusing to set hostname in original namespace\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if sethostname(arg1, strlen(arg1)) != 0 as libc::c_int {
                die_with_error!(
                    b"Can't set hostname to %s\0" as *const u8 as *const libc::c_char,
                    arg1,
                );
            }
        }
        _ => {
            die!(
                b"Unexpected privileged op %d\0" as *const u8 as *const libc::c_char,
                op,
            );
        }
    };
}

unsafe fn setup_newroot(mut unshare_pid: bool, mut privileged_op_socket: libc::c_int) {
    let mut op = 0 as *mut SetupOp;
    let mut tmp_overlay_idx = 0 as libc::c_int;
    let mut current_block_161: u64;
    op = ops;
    while !op.is_null() {
        let mut source = std::ptr::null_mut() as *mut libc::c_char;
        let mut dest = std::ptr::null_mut() as *mut libc::c_char;
        let mut source_mode = 0 as libc::c_int;
        let mut i: libc::c_uint = 0;
        if !((*op).source).is_null()
            && (*op).type_0 as libc::c_uint != SETUP_MAKE_SYMLINK as libc::c_int as libc::c_uint
        {
            source = get_oldroot_path((*op).source);
            source_mode = get_file_mode(source);
            if source_mode < 0 as libc::c_int {
                if (*op).flags as libc::c_uint & ALLOW_NOTEXIST as libc::c_int as libc::c_uint != 0
                    && errno!() == ENOENT
                {
                    current_block_161 = 16668937799742929182;
                } else {
                    die_with_error!(
                        b"Can't get type of source %s\0" as *const u8 as *const libc::c_char,
                        (*op).source,
                    );
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
                        == 0 as libc::c_int as libc::c_uint
                {
                    let mut parent_mode = 0o755 as libc::c_int as libc::c_uint;
                    if (*op).perms >= 0 as libc::c_int
                        && (*op).perms & 0o70 as libc::c_int == 0 as libc::c_int
                    {
                        parent_mode &= !(0o50 as libc::c_uint);
                    }
                    if (*op).perms >= 0 as libc::c_int
                        && (*op).perms & 0o7 as libc::c_int == 0 as libc::c_int
                    {
                        parent_mode &= !(0o5 as libc::c_uint);
                    }
                    dest = get_newroot_path((*op).dest);
                    if mkdir_with_parents(dest, parent_mode, false) != 0 as libc::c_int {
                        die_with_error!(
                            b"Can't mkdir parents for %s\0" as *const u8 as *const libc::c_char,
                            (*op).dest,
                        );
                    }
                }
                static mut cover_proc_dirs: [*const libc::c_char; 4] = [
                    b"sys\0" as *const u8 as *const libc::c_char,
                    b"sysrq-trigger\0" as *const u8 as *const libc::c_char,
                    b"irq\0" as *const u8 as *const libc::c_char,
                    b"bus\0" as *const u8 as *const libc::c_char,
                ];
                static mut devnodes: [*const libc::c_char; 6] = [
                    b"null\0" as *const u8 as *const libc::c_char,
                    b"zero\0" as *const u8 as *const libc::c_char,
                    b"full\0" as *const u8 as *const libc::c_char,
                    b"random\0" as *const u8 as *const libc::c_char,
                    b"urandom\0" as *const u8 as *const libc::c_char,
                    b"tty\0" as *const u8 as *const libc::c_char,
                ];
                static mut stdionodes: [*const libc::c_char; 3] = [
                    b"stdin\0" as *const u8 as *const libc::c_char,
                    b"stdout\0" as *const u8 as *const libc::c_char,
                    b"stderr\0" as *const u8 as *const libc::c_char,
                ];
                match (*op).type_0 as libc::c_uint {
                    1 | 2 | 0 => {
                        if source_mode == S_IFDIR as i32 {
                            if ensure_dir(dest, 0o755 as libc::c_int as mode_t) != 0 as libc::c_int
                            {
                                die_with_error!(
                                    b"Can't mkdir %s\0" as *const u8 as *const libc::c_char,
                                    (*op).dest,
                                );
                            }
                        } else if ensure_file(dest, 0o444 as libc::c_int as mode_t)
                            != 0 as libc::c_int
                        {
                            die_with_error!(
                                b"Can't create file at %s\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        privileged_op(
                            privileged_op_socket,
                            PRIV_SEP_OP_BIND_MOUNT as libc::c_int as u32,
                            ((if (*op).type_0 as libc::c_uint
                                == SETUP_RO_BIND_MOUNT as libc::c_int as libc::c_uint
                            {
                                BIND_READONLY as libc::c_int
                            } else {
                                0 as libc::c_int
                            }) | (if (*op).type_0 as libc::c_uint
                                == SETUP_DEV_BIND_MOUNT as libc::c_int as libc::c_uint
                            {
                                BIND_DEVICES as libc::c_int
                            } else {
                                0 as libc::c_int
                            })) as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as size_t,
                            source,
                            dest,
                        );
                        if (*op).fd >= 0 as libc::c_int {
                            let mut fd_st = std::mem::zeroed();
                            let mut mount_st = std::mem::zeroed();
                            if fstat((*op).fd, &mut fd_st) != 0 as libc::c_int {
                                die_with_error!(
                                    b"Can't stat fd %d\0" as *const u8 as *const libc::c_char,
                                    (*op).fd,
                                );
                            }
                            if lstat(dest, &mut mount_st) != 0 as libc::c_int {
                                die_with_error!(
                                    b"Can't stat mount at %s\0" as *const u8 as *const libc::c_char,
                                    dest,
                                );
                            }
                            if fd_st.st_ino != mount_st.st_ino || fd_st.st_dev != mount_st.st_dev {
                                die_with_error!(
                                    b"Race condition binding dirfd\0" as *const u8
                                        as *const libc::c_char,
                                );
                            }
                            close((*op).fd);
                            (*op).fd = -(1 as libc::c_int);
                        }
                    }
                    3 | 5 | 4 => {
                        let mut sb = {
                            let mut init = StringBuilder {
                                str_0: 0 as *mut libc::c_char,
                                size: 0,
                                offset: 0,
                            };
                            init
                        };
                        let mut multi_src = false;
                        if ensure_dir(dest, 0o755 as libc::c_int as mode_t) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't mkdir %s\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        if !((*op).source).is_null() {
                            strappend(
                                &mut sb,
                                b"upperdir=/oldroot\0" as *const u8 as *const libc::c_char,
                            );
                            strappend_escape_for_mount_options(&mut sb, (*op).source);
                            strappend(
                                &mut sb,
                                b",workdir=/oldroot\0" as *const u8 as *const libc::c_char,
                            );
                            op = (*op).next;
                            strappend_escape_for_mount_options(&mut sb, (*op).source);
                            strappend(&mut sb, b",\0" as *const u8 as *const libc::c_char);
                        } else if (*op).type_0 as libc::c_uint
                            == SETUP_TMP_OVERLAY_MOUNT as libc::c_int as libc::c_uint
                        {
                            let fresh3 = tmp_overlay_idx;
                            tmp_overlay_idx = tmp_overlay_idx + 1;
                            strappendf(
                                &mut sb as *mut StringBuilder,
                                b"upperdir=/tmp-overlay-upper-%1$d,workdir=/tmp-overlay-work-%1$d,\0"
                                    as *const u8 as *const libc::c_char,
                                fresh3,
                            );
                        }
                        strappend(
                            &mut sb,
                            b"lowerdir=/oldroot\0" as *const u8 as *const libc::c_char,
                        );
                        while !((*op).next).is_null()
                            && (*(*op).next).type_0 as libc::c_uint
                                == SETUP_OVERLAY_SRC as libc::c_int as libc::c_uint
                        {
                            op = (*op).next;
                            if multi_src {
                                strappend(
                                    &mut sb,
                                    b":/oldroot\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            strappend_escape_for_mount_options(&mut sb, (*op).source);
                            multi_src = true;
                        }
                        strappend(&mut sb, b",userxattr\0" as *const u8 as *const libc::c_char);
                        privileged_op(
                            privileged_op_socket,
                            PRIV_SEP_OP_OVERLAY_MOUNT as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as size_t,
                            sb.str_0,
                            dest,
                        );
                        free(sb.str_0 as *mut libc::c_void);
                    }
                    16 => {
                        privileged_op(
                            privileged_op_socket,
                            PRIV_SEP_OP_REMOUNT_RO_NO_RECURSIVE as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as size_t,
                            std::ptr::null_mut() as *const libc::c_char,
                            dest,
                        );
                    }
                    7 => {
                        if ensure_dir(dest, 0o755 as libc::c_int as mode_t) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't mkdir %s\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        if unshare_pid as libc::c_int != 0 || opt_pidns_fd != -(1 as libc::c_int) {
                            privileged_op(
                                privileged_op_socket,
                                PRIV_SEP_OP_PROC_MOUNT as libc::c_int as u32,
                                0 as libc::c_int as u32,
                                0 as libc::c_int as u32,
                                0 as libc::c_int as size_t,
                                dest,
                                std::ptr::null_mut() as *const libc::c_char,
                            );
                        } else {
                            privileged_op(
                                privileged_op_socket,
                                PRIV_SEP_OP_BIND_MOUNT as libc::c_int as u32,
                                0 as libc::c_int as u32,
                                0 as libc::c_int as u32,
                                0 as libc::c_int as size_t,
                                b"oldroot/proc\0" as *const u8 as *const libc::c_char,
                                dest,
                            );
                        }
                        i = 0 as libc::c_int as libc::c_uint;
                        while (i as libc::c_ulong)
                            < (::core::mem::size_of::<[*const libc::c_char; 4]>() as libc::c_ulong)
                                .wrapping_div(
                                    ::core::mem::size_of::<*const libc::c_char>() as libc::c_ulong
                                )
                        {
                            let mut subdir = strconcat3(
                                dest,
                                b"/\0" as *const u8 as *const libc::c_char,
                                cover_proc_dirs[i as usize],
                            );
                            if access(subdir, W_OK) < 0 as libc::c_int {
                                if !(errno!() == EACCES || errno!() == ENOENT || errno!() == EROFS)
                                {
                                    die_with_error!(
                                        b"Can't access %s\0" as *const u8 as *const libc::c_char,
                                        subdir,
                                    );
                                }
                            } else {
                                privileged_op(
                                    privileged_op_socket,
                                    PRIV_SEP_OP_BIND_MOUNT as libc::c_int as u32,
                                    BIND_READONLY as libc::c_int as u32,
                                    0 as libc::c_int as u32,
                                    0 as libc::c_int as size_t,
                                    subdir,
                                    subdir,
                                );
                            }
                            i = i.wrapping_add(1);
                        }
                    }
                    8 => {
                        if ensure_dir(dest, 0o755 as libc::c_int as mode_t) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't mkdir %s\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        privileged_op(
                            privileged_op_socket,
                            PRIV_SEP_OP_TMPFS_MOUNT as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0o755 as libc::c_int as u32,
                            0 as libc::c_int as size_t,
                            dest,
                            std::ptr::null_mut() as *const libc::c_char,
                        );
                        i = 0 as libc::c_int as libc::c_uint;
                        while (i as libc::c_ulong)
                            < (::core::mem::size_of::<[*const libc::c_char; 6]>() as libc::c_ulong)
                                .wrapping_div(
                                    ::core::mem::size_of::<*const libc::c_char>() as libc::c_ulong
                                )
                        {
                            let mut node_dest = strconcat3(
                                dest,
                                b"/\0" as *const u8 as *const libc::c_char,
                                devnodes[i as usize],
                            );
                            let mut node_src = strconcat(
                                b"/oldroot/dev/\0" as *const u8 as *const libc::c_char,
                                devnodes[i as usize],
                            );
                            if create_file(
                                node_dest,
                                0o444 as libc::c_int as mode_t,
                                std::ptr::null_mut() as *const libc::c_char,
                            ) != 0 as libc::c_int
                            {
                                die_with_error!(
                                    b"Can't create file %s/%s\0" as *const u8
                                        as *const libc::c_char,
                                    (*op).dest,
                                    devnodes[i as usize],
                                );
                            }
                            privileged_op(
                                privileged_op_socket,
                                PRIV_SEP_OP_BIND_MOUNT as libc::c_int as u32,
                                BIND_DEVICES as libc::c_int as u32,
                                0 as libc::c_int as u32,
                                0 as libc::c_int as size_t,
                                node_src,
                                node_dest,
                            );
                            i = i.wrapping_add(1);
                        }
                        i = 0 as libc::c_int as libc::c_uint;
                        while (i as libc::c_ulong)
                            < (::core::mem::size_of::<[*const libc::c_char; 3]>() as libc::c_ulong)
                                .wrapping_div(
                                    ::core::mem::size_of::<*const libc::c_char>() as libc::c_ulong
                                )
                        {
                            let mut target = xasprintf(
                                b"/proc/self/fd/%d\0" as *const u8 as *const libc::c_char,
                                i,
                            );
                            let mut node_dest_0 = strconcat3(
                                dest,
                                b"/\0" as *const u8 as *const libc::c_char,
                                stdionodes[i as usize],
                            );
                            if symlink(target, node_dest_0) < 0 as libc::c_int {
                                die_with_error!(
                                    b"Can't create symlink %s/%s\0" as *const u8
                                        as *const libc::c_char,
                                    (*op).dest,
                                    stdionodes[i as usize],
                                );
                            }
                            i = i.wrapping_add(1);
                        }
                        let mut dev_fd =
                            strconcat(dest, b"/fd\0" as *const u8 as *const libc::c_char);
                        if symlink(
                            b"/proc/self/fd\0" as *const u8 as *const libc::c_char,
                            dev_fd,
                        ) < 0 as libc::c_int
                        {
                            die_with_error!(
                                b"Can't create symlink %s\0" as *const u8 as *const libc::c_char,
                                dev_fd,
                            );
                        }
                        let mut dev_core =
                            strconcat(dest, b"/core\0" as *const u8 as *const libc::c_char);
                        if symlink(
                            b"/proc/kcore\0" as *const u8 as *const libc::c_char,
                            dev_core,
                        ) < 0 as libc::c_int
                        {
                            die_with_error!(
                                b"Can't create symlink %s\0" as *const u8 as *const libc::c_char,
                                dev_core,
                            );
                        }
                        let mut pts =
                            strconcat(dest, b"/pts\0" as *const u8 as *const libc::c_char);
                        let mut ptmx =
                            strconcat(dest, b"/ptmx\0" as *const u8 as *const libc::c_char);
                        let mut shm =
                            strconcat(dest, b"/shm\0" as *const u8 as *const libc::c_char);
                        if mkdir(shm, 0o755 as libc::c_int as mode_t) == -(1 as libc::c_int) {
                            die_with_error!(
                                b"Can't create %s/shm\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        if mkdir(pts, 0o755 as libc::c_int as mode_t) == -(1 as libc::c_int) {
                            die_with_error!(
                                b"Can't create %s/devpts\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        privileged_op(
                            privileged_op_socket,
                            PRIV_SEP_OP_DEVPTS_MOUNT as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as size_t,
                            pts,
                            std::ptr::null_mut() as *const libc::c_char,
                        );
                        if symlink(b"pts/ptmx\0" as *const u8 as *const libc::c_char, ptmx)
                            != 0 as libc::c_int
                        {
                            die_with_error!(
                                b"Can't make symlink at %s/ptmx\0" as *const u8
                                    as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        if !host_tty_dev.is_null()
                            && *host_tty_dev as libc::c_int != 0 as libc::c_int
                        {
                            let mut src_tty_dev = strconcat(
                                b"/oldroot\0" as *const u8 as *const libc::c_char,
                                host_tty_dev,
                            );
                            let mut dest_console =
                                strconcat(dest, b"/console\0" as *const u8 as *const libc::c_char);
                            if create_file(
                                dest_console,
                                0o444 as libc::c_int as mode_t,
                                std::ptr::null_mut() as *const libc::c_char,
                            ) != 0 as libc::c_int
                            {
                                die_with_error!(
                                    b"creating %s/console\0" as *const u8 as *const libc::c_char,
                                    (*op).dest,
                                );
                            }
                            privileged_op(
                                privileged_op_socket,
                                PRIV_SEP_OP_BIND_MOUNT as libc::c_int as u32,
                                BIND_DEVICES as libc::c_int as u32,
                                0 as libc::c_int as u32,
                                0 as libc::c_int as size_t,
                                src_tty_dev,
                                dest_console,
                            );
                        }
                    }
                    9 => {
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0 as libc::c_int);
                        assert!((*op).perms <= 0o7777 as libc::c_int);
                        if ensure_dir(dest, 0o755 as libc::c_int as mode_t) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't mkdir %s\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        privileged_op(
                            privileged_op_socket,
                            PRIV_SEP_OP_TMPFS_MOUNT as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            (*op).perms as u32,
                            (*op).size,
                            dest,
                            std::ptr::null_mut() as *const libc::c_char,
                        );
                    }
                    10 => {
                        if ensure_dir(dest, 0o755 as libc::c_int as mode_t) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't mkdir %s\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        privileged_op(
                            privileged_op_socket,
                            PRIV_SEP_OP_MQUEUE_MOUNT as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as size_t,
                            dest,
                            std::ptr::null_mut() as *const libc::c_char,
                        );
                    }
                    11 => {
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0 as libc::c_int);
                        assert!((*op).perms <= 0o7777 as libc::c_int);
                        if ensure_dir(dest, (*op).perms as mode_t) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't mkdir %s\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                    }
                    18 => {
                        assert!(!((*op).dest).is_null());
                        assert!(dest.is_null());
                        dest = get_newroot_path((*op).dest);
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0 as libc::c_int);
                        assert!((*op).perms <= 0o7777 as libc::c_int);
                        if chmod(dest, (*op).perms as mode_t) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't chmod %#o %s\0" as *const u8 as *const libc::c_char,
                                (*op).perms,
                                (*op).dest,
                            );
                        }
                    }
                    12 => {
                        let mut dest_fd = -(1 as libc::c_int);
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0 as libc::c_int);
                        assert!((*op).perms <= 0o7777 as libc::c_int);
                        dest_fd = creat(dest, (*op).perms as mode_t);
                        if dest_fd == -(1 as libc::c_int) {
                            die_with_error!(
                                b"Can't create file %s\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        if copy_file_data((*op).fd, dest_fd) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't write data to file %s\0" as *const u8
                                    as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        close((*op).fd);
                        (*op).fd = -(1 as libc::c_int);
                    }
                    13 | 14 => {
                        let mut dest_fd_0 = -(1 as libc::c_int);
                        let mut tempfile: [libc::c_char; 16] =
                            *::core::mem::transmute::<&[u8; 16], &mut [libc::c_char; 16]>(
                                b"/bindfileXXXXXX\0",
                            );
                        assert!(!dest.is_null());
                        assert!((*op).perms >= 0 as libc::c_int);
                        assert!((*op).perms <= 0o7777 as libc::c_int);
                        dest_fd_0 = mkstemp(tempfile.as_mut_ptr());
                        if dest_fd_0 == -(1 as libc::c_int) {
                            die_with_error!(
                                b"Can't create tmpfile for %s\0" as *const u8
                                    as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        if fchmod(dest_fd_0, (*op).perms as mode_t) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't set mode %#o on file to be used for %s\0" as *const u8
                                    as *const libc::c_char,
                                (*op).perms,
                                (*op).dest,
                            );
                        }
                        if copy_file_data((*op).fd, dest_fd_0) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't write data to file %s\0" as *const u8
                                    as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        close((*op).fd);
                        (*op).fd = -(1 as libc::c_int);
                        assert!(!dest.is_null());
                        if ensure_file(dest, 0o444 as libc::c_int as mode_t) != 0 as libc::c_int {
                            die_with_error!(
                                b"Can't create file at %s\0" as *const u8 as *const libc::c_char,
                                (*op).dest,
                            );
                        }
                        privileged_op(
                            privileged_op_socket,
                            PRIV_SEP_OP_BIND_MOUNT as libc::c_int as u32,
                            (if (*op).type_0 as libc::c_uint
                                == SETUP_MAKE_RO_BIND_FILE as libc::c_int as libc::c_uint
                            {
                                BIND_READONLY as libc::c_int
                            } else {
                                0 as libc::c_int
                            }) as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as size_t,
                            tempfile.as_mut_ptr(),
                            dest,
                        );
                        unlink(tempfile.as_mut_ptr());
                    }
                    15 => {
                        assert!(!((*op).source).is_null());
                        if symlink((*op).source, dest) != 0 as libc::c_int {
                            if errno!() == EEXIST {
                                let mut existing = readlink_malloc(dest);
                                if existing.is_null() {
                                    if errno!() == EINVAL {
                                        die!(
                                            b"Can't make symlink at %s: destination exists and is not a symlink\0"
                                                as *const u8 as *const libc::c_char,
                                            (*op).dest,
                                        );
                                    } else {
                                        die_with_error!(
                                            b"Can't make symlink at %s: destination exists, and cannot read symlink target\0"
                                                as *const u8 as *const libc::c_char,
                                            (*op).dest,
                                        );
                                    }
                                }
                                if !(strcmp(existing, (*op).source) == 0 as libc::c_int) {
                                    die!(
                                        b"Can't make symlink at %s: existing destination is %s\0"
                                            as *const u8
                                            as *const libc::c_char,
                                        (*op).dest,
                                        existing,
                                    );
                                }
                            } else {
                                die_with_error!(
                                    b"Can't make symlink at %s\0" as *const u8
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
                            PRIV_SEP_OP_SET_HOSTNAME as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as u32,
                            0 as libc::c_int as size_t,
                            (*op).dest,
                            std::ptr::null_mut() as *const libc::c_char,
                        );
                    }
                    6 | _ => {
                        die!(
                            b"Unexpected type %d\0" as *const u8 as *const libc::c_char,
                            (*op).type_0 as libc::c_uint,
                        );
                    }
                }
            }
            _ => {}
        }
        op = (*op).next;
    }
    privileged_op(
        privileged_op_socket,
        PRIV_SEP_OP_DONE as libc::c_int as u32,
        0 as libc::c_int as u32,
        0 as libc::c_int as u32,
        0 as libc::c_int as size_t,
        std::ptr::null_mut() as *const libc::c_char,
        std::ptr::null_mut() as *const libc::c_char,
    );
}

unsafe fn close_ops_fd() {
    let mut op = 0 as *mut SetupOp;
    op = ops;
    while !op.is_null() {
        if (*op).fd != -(1 as libc::c_int) {
            close((*op).fd);
            (*op).fd = -(1 as libc::c_int);
        }
        op = (*op).next;
    }
}

unsafe fn resolve_symlinks_in_ops() {
    let mut op = 0 as *mut SetupOp;
    op = ops;
    while !op.is_null() {
        let mut old_source = 0 as *const libc::c_char;
        match (*op).type_0 as libc::c_uint {
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
                        die_with_error!(
                            b"Can't find source path %s\0" as *const u8 as *const libc::c_char,
                            old_source,
                        );
                    }
                }
            }
            5 | 4 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | _ => {}
        }
        op = (*op).next;
    }
}

unsafe fn resolve_string_offset(
    mut buffer: *mut libc::c_void,
    mut buffer_size: size_t,
    mut offset: u32,
) -> *const libc::c_char {
    if offset == 0 as libc::c_int as libc::c_uint {
        return std::ptr::null_mut() as *const libc::c_char;
    }
    if offset > buffer_size as u32 {
        die!(
            b"Invalid string offset %d (buffer size %zd)\0" as *const u8 as *const libc::c_char,
            offset,
            buffer_size,
        );
    }
    return (buffer as *const libc::c_char).offset(offset as isize);
}

unsafe fn read_priv_sec_op(
    mut read_socket: libc::c_int,
    mut buffer: *mut libc::c_void,
    mut buffer_size: size_t,
    mut flags: *mut u32,
    mut perms: *mut u32,
    mut size_arg: *mut size_t,
    mut arg1: *mut *const libc::c_char,
    mut arg2: *mut *const libc::c_char,
) -> u32 {
    let mut op = buffer as *const PrivSepOp;
    let mut rec_len: ssize_t = 0;
    loop {
        rec_len = read(read_socket, buffer, buffer_size.wrapping_sub(1));
        if !(rec_len == -(1) && errno!() == EINTR) {
            break;
        }
    }
    if rec_len < 0 {
        die_with_error!(
            b"Can't read from unprivileged helper\0" as *const u8 as *const libc::c_char,
        );
    }
    if rec_len == 0 {
        exit(1 as libc::c_int);
    }
    if (rec_len as size_t) < ::core::mem::size_of::<PrivSepOp>() {
        die!(
            b"Invalid size %zd from unprivileged helper\0" as *const u8 as *const libc::c_char,
            rec_len,
        );
    }
    *(buffer as *mut libc::c_char).offset(rec_len as isize) = 0 as libc::c_int as libc::c_char;
    *flags = (*op).flags;
    *perms = (*op).perms;
    *size_arg = (*op).size_arg;
    *arg1 = resolve_string_offset(buffer, rec_len as size_t, (*op).arg1_offset);
    *arg2 = resolve_string_offset(buffer, rec_len as size_t, (*op).arg2_offset);
    return (*op).op;
}

unsafe fn print_version_and_exit() -> ! {
    printf(
        b"%s\n\0" as *const u8 as *const libc::c_char,
        PACKAGE_STRING.as_ptr(),
    );
    exit(0 as libc::c_int);
}

unsafe fn is_modifier_option(mut option: *const libc::c_char) -> libc::c_int {
    return (strcmp(option, b"--perms\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        || strcmp(option, b"--size\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int)
        as libc::c_int;
}

unsafe fn warn_only_last_option(mut _name: *const libc::c_char) {
    bwrap_log!(
        LOG_WARNING,
        b"Only the last %s option will take effect\0" as *const u8 as *const libc::c_char,
        name,
    );
}

unsafe fn make_setup_overlay_src_ops(argv: *const *const libc::c_char) {
    let mut i: libc::c_int = 0;
    let mut op = 0 as *mut SetupOp;
    i = 1 as libc::c_int;
    while i <= next_overlay_src_count {
        op = setup_op_new(SETUP_OVERLAY_SRC);
        (*op).source = *argv.offset((1 as libc::c_int - 2 as libc::c_int * i) as isize);
        i += 1;
    }
    next_overlay_src_count = 0 as libc::c_int;
}

unsafe fn parse_args_recurse(
    mut argcp: *mut libc::c_int,
    mut argvp: *mut *mut *const libc::c_char,
    mut in_file: bool,
    mut total_parsed_argc_p: *mut libc::c_int,
) {
    let mut op = 0 as *mut SetupOp;
    let mut argc = *argcp;
    let mut argv = *argvp;
    static mut MAX_ARGS: i32 = 9000 as libc::c_int;
    if *total_parsed_argc_p > MAX_ARGS {
        die!(
            b"Exceeded maximum number of arguments %u\0" as *const u8 as *const libc::c_char,
            MAX_ARGS,
        );
    }
    while argc > 0 as libc::c_int {
        let mut arg = *argv.offset(0 as libc::c_int as isize);
        if strcmp(arg, b"--help\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            usage(EXIT_SUCCESS, stdout);
        } else if strcmp(arg, b"--version\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            print_version_and_exit();
        } else if strcmp(arg, b"--args\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
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
                die!(
                    b"--args not supported in arguments file\0" as *const u8 as *const libc::c_char
                );
            }
            if argc < 2 as libc::c_int {
                die!(b"--args takes an argument\0" as *const u8 as *const libc::c_char);
            }
            the_fd = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_args_data = load_file_data(the_fd, &mut data_len);
            if opt_args_data.is_null() {
                die_with_error!(b"Can't read --args data\0" as *const u8 as *const libc::c_char);
            }
            close(the_fd);
            data_end = opt_args_data.offset(data_len as isize);
            data_argc = 0 as libc::c_int;
            p = opt_args_data;
            while !p.is_null() && p < data_end {
                data_argc += 1;
                *total_parsed_argc_p += 1;
                if *total_parsed_argc_p > MAX_ARGS {
                    die!(
                        b"Exceeded maximum number of arguments %u\0" as *const u8
                            as *const libc::c_char,
                        MAX_ARGS,
                    );
                }
                p = memchr(
                    p as *const libc::c_void,
                    0 as libc::c_int,
                    (data_end).offset_from(p) as usize,
                ) as *const libc::c_char;
                if !p.is_null() {
                    p = p.offset(1);
                }
            }
            data_argv = xcalloc(
                (data_argc + 1 as libc::c_int) as size_t,
                ::core::mem::size_of::<*mut libc::c_char>(),
            ) as *mut *const libc::c_char;
            i = 0 as libc::c_int;
            p = opt_args_data;
            while !p.is_null() && p < data_end {
                let fresh4 = i;
                i = i + 1;
                let ref mut fresh5 = *data_argv.offset(fresh4 as isize);
                *fresh5 = p;
                p = memchr(
                    p as *const libc::c_void,
                    0 as libc::c_int,
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
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--argv0\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--argv0 takes one argument\0" as *const u8 as *const libc::c_char);
            }
            if !opt_argv0.is_null() {
                die!(b"--argv0 used multiple times\0" as *const u8 as *const libc::c_char);
            }
            opt_argv0 = *argv.offset(1 as libc::c_int as isize);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, b"--level-prefix\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            bwrap_level_prefix = true;
        } else if strcmp(arg, b"--unshare-all\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            opt_unshare_net = true;
            opt_unshare_cgroup_try = opt_unshare_net;
            opt_unshare_uts = opt_unshare_cgroup_try;
            opt_unshare_pid = opt_unshare_uts;
            opt_unshare_ipc = opt_unshare_pid;
            opt_unshare_user_try = opt_unshare_ipc;
        } else if strcmp(arg, b"--unshare-user\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            opt_unshare_user = true;
        } else if strcmp(
            arg,
            b"--unshare-user-try\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            opt_unshare_user_try = true;
        } else if strcmp(arg, b"--unshare-ipc\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            opt_unshare_ipc = true;
        } else if strcmp(arg, b"--unshare-pid\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            opt_unshare_pid = true;
        } else if strcmp(arg, b"--unshare-net\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            opt_unshare_net = true;
        } else if strcmp(arg, b"--unshare-uts\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            opt_unshare_uts = true;
        } else if strcmp(
            arg,
            b"--unshare-cgroup\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            opt_unshare_cgroup = true;
        } else if strcmp(
            arg,
            b"--unshare-cgroup-try\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            opt_unshare_cgroup_try = true;
        } else if strcmp(arg, b"--share-net\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            opt_unshare_net = false;
        } else if strcmp(arg, b"--chdir\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--chdir takes one argument\0" as *const u8 as *const libc::c_char);
            }
            if !opt_chdir_path.is_null() {
                warn_only_last_option(b"--chdir\0" as *const u8 as *const libc::c_char);
            }
            opt_chdir_path = *argv.offset(1 as libc::c_int as isize);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(
            arg,
            b"--disable-userns\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            opt_disable_userns = true;
        } else if strcmp(
            arg,
            b"--assert-userns-disabled\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            opt_assert_userns_disabled = true;
        } else if strcmp(arg, b"--remount-ro\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--remount-ro takes one argument\0" as *const u8 as *const libc::c_char);
            }
            op = setup_op_new(SETUP_REMOUNT_RO_NO_RECURSIVE);
            (*op).dest = *argv.offset(1 as libc::c_int as isize);
            argv = argv.offset(1);
            argc -= 1;
        } else if strcmp(arg, b"--bind\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            || strcmp(arg, b"--bind-try\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            if argc < 3 as libc::c_int {
                die!(
                    b"%s takes two arguments\0" as *const u8 as *const libc::c_char,
                    arg,
                );
            }
            op = setup_op_new(SETUP_BIND_MOUNT);
            (*op).source = *argv.offset(1 as libc::c_int as isize);
            (*op).dest = *argv.offset(2 as libc::c_int as isize);
            if strcmp(arg, b"--bind-try\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                (*op).flags = ALLOW_NOTEXIST;
            }
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--ro-bind\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
            || strcmp(arg, b"--ro-bind-try\0" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
        {
            if argc < 3 as libc::c_int {
                die!(
                    b"%s takes two arguments\0" as *const u8 as *const libc::c_char,
                    arg,
                );
            }
            op = setup_op_new(SETUP_RO_BIND_MOUNT);
            (*op).source = *argv.offset(1 as libc::c_int as isize);
            (*op).dest = *argv.offset(2 as libc::c_int as isize);
            if strcmp(arg, b"--ro-bind-try\0" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                (*op).flags = ALLOW_NOTEXIST;
            }
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--dev-bind\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
            || strcmp(arg, b"--dev-bind-try\0" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
        {
            if argc < 3 as libc::c_int {
                die!(
                    b"%s takes two arguments\0" as *const u8 as *const libc::c_char,
                    arg,
                );
            }
            op = setup_op_new(SETUP_DEV_BIND_MOUNT);
            (*op).source = *argv.offset(1 as libc::c_int as isize);
            (*op).dest = *argv.offset(2 as libc::c_int as isize);
            if strcmp(arg, b"--dev-bind-try\0" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                (*op).flags = ALLOW_NOTEXIST;
            }
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--bind-fd\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
            || strcmp(arg, b"--ro-bind-fd\0" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
        {
            let mut src_fd: libc::c_int = 0;
            let mut endptr_0 = 0 as *mut libc::c_char;
            if argc < 3 as libc::c_int {
                die!(b"--bind-fd takes two arguments\0" as *const u8 as *const libc::c_char);
            }
            src_fd = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_0,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_0.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || src_fd < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            if strcmp(arg, b"--ro-bind-fd\0" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                op = setup_op_new(SETUP_RO_BIND_MOUNT);
            } else {
                op = setup_op_new(SETUP_BIND_MOUNT);
            }
            (*op).source = xasprintf(
                b"/proc/self/fd/%d\0" as *const u8 as *const libc::c_char,
                src_fd,
            );
            (*op).fd = src_fd;
            (*op).dest = *argv.offset(2 as libc::c_int as isize);
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--overlay-src\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if is_privileged {
                die!(
                    b"The --overlay-src option is not permitted in setuid mode\0" as *const u8
                        as *const libc::c_char,
                );
            }
            next_overlay_src_count += 1;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--overlay\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut workdir_op = 0 as *mut SetupOp;
            if is_privileged {
                die!(
                    b"The --overlay option is not permitted in setuid mode\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if argc < 4 as libc::c_int {
                die!(b"--overlay takes three arguments\0" as *const u8 as *const libc::c_char);
            }
            if next_overlay_src_count < 1 as libc::c_int {
                die!(
                    b"--overlay requires at least one --overlay-src\0" as *const u8
                        as *const libc::c_char,
                );
            }
            op = setup_op_new(SETUP_OVERLAY_MOUNT);
            (*op).source = *argv.offset(1 as libc::c_int as isize);
            workdir_op = setup_op_new(SETUP_OVERLAY_SRC);
            (*workdir_op).source = *argv.offset(2 as libc::c_int as isize);
            (*op).dest = *argv.offset(3 as libc::c_int as isize);
            make_setup_overlay_src_ops(argv);
            argv = argv.offset(3 as libc::c_int as isize);
            argc -= 3 as libc::c_int;
        } else if strcmp(arg, b"--tmp-overlay\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if is_privileged {
                die!(
                    b"The --tmp-overlay option is not permitted in setuid mode\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if argc < 2 as libc::c_int {
                die!(b"--tmp-overlay takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if next_overlay_src_count < 1 as libc::c_int {
                die!(
                    b"--tmp-overlay requires at least one --overlay-src\0" as *const u8
                        as *const libc::c_char,
                );
            }
            op = setup_op_new(SETUP_TMP_OVERLAY_MOUNT);
            (*op).dest = *argv.offset(1 as libc::c_int as isize);
            make_setup_overlay_src_ops(argv);
            opt_tmp_overlay_count += 1;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--ro-overlay\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if is_privileged {
                die!(
                    b"The --ro-overlay option is not permitted in setuid mode\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if argc < 2 as libc::c_int {
                die!(b"--ro-overlay takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if next_overlay_src_count < 2 as libc::c_int {
                die!(
                    b"--ro-overlay requires at least two --overlay-src\0" as *const u8
                        as *const libc::c_char,
                );
            }
            op = setup_op_new(SETUP_RO_OVERLAY_MOUNT);
            (*op).dest = *argv.offset(1 as libc::c_int as isize);
            make_setup_overlay_src_ops(argv);
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--proc\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            if argc < 2 as libc::c_int {
                die!(b"--proc takes an argument\0" as *const u8 as *const libc::c_char);
            }
            op = setup_op_new(SETUP_MOUNT_PROC);
            (*op).dest = *argv.offset(1 as libc::c_int as isize);
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--exec-label\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--exec-label takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if !opt_exec_label.is_null() {
                warn_only_last_option(b"--exec-label\0" as *const u8 as *const libc::c_char);
            }
            opt_exec_label = *argv.offset(1 as libc::c_int as isize);
            die_unless_label_valid(opt_exec_label);
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--file-label\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--file-label takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if !opt_file_label.is_null() {
                warn_only_last_option(b"--file-label\0" as *const u8 as *const libc::c_char);
            }
            opt_file_label = *argv.offset(1 as libc::c_int as isize);
            die_unless_label_valid(opt_file_label);
            if label_create_file(opt_file_label) != 0 {
                die_with_error!(b"--file-label setup failed\0" as *const u8 as *const libc::c_char);
            }
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--dev\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            if argc < 2 as libc::c_int {
                die!(b"--dev takes an argument\0" as *const u8 as *const libc::c_char);
            }
            op = setup_op_new(SETUP_MOUNT_DEV);
            (*op).dest = *argv.offset(1 as libc::c_int as isize);
            opt_needs_devpts = true;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--tmpfs\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--tmpfs takes an argument\0" as *const u8 as *const libc::c_char);
            }
            op = setup_op_new(SETUP_MOUNT_TMPFS);
            (*op).dest = *argv.offset(1 as libc::c_int as isize);
            if next_perms >= 0 as libc::c_int {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o755 as libc::c_int;
            }
            next_perms = -(1 as libc::c_int);
            (*op).size = next_size_arg;
            next_size_arg = 0 as libc::c_int as size_t;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--mqueue\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--mqueue takes an argument\0" as *const u8 as *const libc::c_char);
            }
            op = setup_op_new(SETUP_MOUNT_MQUEUE);
            (*op).dest = *argv.offset(1 as libc::c_int as isize);
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--dir\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            if argc < 2 as libc::c_int {
                die!(b"--dir takes an argument\0" as *const u8 as *const libc::c_char);
            }
            op = setup_op_new(SETUP_MAKE_DIR);
            (*op).dest = *argv.offset(1 as libc::c_int as isize);
            if next_perms >= 0 as libc::c_int {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o755 as libc::c_int;
            }
            next_perms = -(1 as libc::c_int);
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--file\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            let mut file_fd: libc::c_int = 0;
            let mut endptr_1 = 0 as *mut libc::c_char;
            if argc < 3 as libc::c_int {
                die!(b"--file takes two arguments\0" as *const u8 as *const libc::c_char);
            }
            file_fd = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_1,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_1.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || file_fd < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            op = setup_op_new(SETUP_MAKE_FILE);
            (*op).fd = file_fd;
            (*op).dest = *argv.offset(2 as libc::c_int as isize);
            if next_perms >= 0 as libc::c_int {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o666 as libc::c_int;
            }
            next_perms = -(1 as libc::c_int);
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--bind-data\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut file_fd_0: libc::c_int = 0;
            let mut endptr_2 = 0 as *mut libc::c_char;
            if argc < 3 as libc::c_int {
                die!(b"--bind-data takes two arguments\0" as *const u8 as *const libc::c_char);
            }
            file_fd_0 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_2,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_2.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || file_fd_0 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            op = setup_op_new(SETUP_MAKE_BIND_FILE);
            (*op).fd = file_fd_0;
            (*op).dest = *argv.offset(2 as libc::c_int as isize);
            if next_perms >= 0 as libc::c_int {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o600 as libc::c_int;
            }
            next_perms = -(1 as libc::c_int);
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--ro-bind-data\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut file_fd_1: libc::c_int = 0;
            let mut endptr_3 = 0 as *mut libc::c_char;
            if argc < 3 as libc::c_int {
                die!(b"--ro-bind-data takes two arguments\0" as *const u8 as *const libc::c_char);
            }
            file_fd_1 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_3,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_3.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || file_fd_1 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            op = setup_op_new(SETUP_MAKE_RO_BIND_FILE);
            (*op).fd = file_fd_1;
            (*op).dest = *argv.offset(2 as libc::c_int as isize);
            if next_perms >= 0 as libc::c_int {
                (*op).perms = next_perms;
            } else {
                (*op).perms = 0o600 as libc::c_int;
            }
            next_perms = -(1 as libc::c_int);
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--symlink\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if argc < 3 as libc::c_int {
                die!(b"--symlink takes two arguments\0" as *const u8 as *const libc::c_char);
            }
            op = setup_op_new(SETUP_MAKE_SYMLINK);
            (*op).source = *argv.offset(1 as libc::c_int as isize);
            (*op).dest = *argv.offset(2 as libc::c_int as isize);
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--lock-file\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--lock-file takes an argument\0" as *const u8 as *const libc::c_char);
            }
            lock_file_new(*argv.offset(1 as libc::c_int as isize));
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--sync-fd\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut the_fd_0: libc::c_int = 0;
            let mut endptr_4 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--sync-fd takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_sync_fd != -(1 as libc::c_int) {
                warn_only_last_option(b"--sync-fd\0" as *const u8 as *const libc::c_char);
            }
            the_fd_0 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_4,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_4.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_0 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_sync_fd = the_fd_0;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--block-fd\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut the_fd_1: libc::c_int = 0;
            let mut endptr_5 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--block-fd takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_block_fd != -(1 as libc::c_int) {
                warn_only_last_option(b"--block-fd\0" as *const u8 as *const libc::c_char);
            }
            the_fd_1 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_5,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_5.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_1 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_block_fd = the_fd_1;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(
            arg,
            b"--userns-block-fd\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            let mut the_fd_2: libc::c_int = 0;
            let mut endptr_6 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--userns-block-fd takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_userns_block_fd != -(1 as libc::c_int) {
                warn_only_last_option(b"--userns-block-fd\0" as *const u8 as *const libc::c_char);
            }
            the_fd_2 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_6,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_6.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_2 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_userns_block_fd = the_fd_2;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--info-fd\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut the_fd_3: libc::c_int = 0;
            let mut endptr_7 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--info-fd takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_info_fd != -(1 as libc::c_int) {
                warn_only_last_option(b"--info-fd\0" as *const u8 as *const libc::c_char);
            }
            the_fd_3 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_7,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_7.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_3 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_info_fd = the_fd_3;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(
            arg,
            b"--json-status-fd\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            let mut the_fd_4: libc::c_int = 0;
            let mut endptr_8 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--json-status-fd takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_json_status_fd != -(1 as libc::c_int) {
                warn_only_last_option(b"--json-status-fd\0" as *const u8 as *const libc::c_char);
            }
            the_fd_4 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_8,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_8.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_4 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_json_status_fd = the_fd_4;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--seccomp\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut the_fd_5: libc::c_int = 0;
            let mut endptr_9 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--seccomp takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if !seccomp_programs.is_null() {
                die!(
                    b"--seccomp cannot be combined with --add-seccomp-fd\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if opt_seccomp_fd != -(1 as libc::c_int) {
                warn_only_last_option(b"--seccomp\0" as *const u8 as *const libc::c_char);
            }
            the_fd_5 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_9,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_9.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_5 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_seccomp_fd = the_fd_5;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(
            arg,
            b"--add-seccomp-fd\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            let mut the_fd_6: libc::c_int = 0;
            let mut endptr_10 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--add-seccomp-fd takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_seccomp_fd != -(1 as libc::c_int) {
                die!(
                    b"--add-seccomp-fd cannot be combined with --seccomp\0" as *const u8
                        as *const libc::c_char,
                );
            }
            the_fd_6 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_10,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_10.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_6 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            seccomp_program_new(&mut the_fd_6);
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--userns\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            let mut the_fd_7: libc::c_int = 0;
            let mut endptr_11 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--userns takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_userns_fd != -(1 as libc::c_int) {
                warn_only_last_option(b"--userns\0" as *const u8 as *const libc::c_char);
            }
            the_fd_7 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_11,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_11.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_7 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_userns_fd = the_fd_7;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--userns2\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut the_fd_8: libc::c_int = 0;
            let mut endptr_12 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--userns2 takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_userns2_fd != -(1 as libc::c_int) {
                warn_only_last_option(b"--userns2\0" as *const u8 as *const libc::c_char);
            }
            the_fd_8 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_12,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_12.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_8 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_userns2_fd = the_fd_8;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--pidns\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            let mut the_fd_9: libc::c_int = 0;
            let mut endptr_13 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--pidns takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_pidns_fd != -(1 as libc::c_int) {
                warn_only_last_option(b"--pidns\0" as *const u8 as *const libc::c_char);
            }
            the_fd_9 = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_13,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_13.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_fd_9 < 0 as libc::c_int
            {
                die!(
                    b"Invalid fd: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_pidns_fd = the_fd_9;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--clearenv\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            xclearenv();
        } else if strcmp(arg, b"--setenv\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            if argc < 3 as libc::c_int {
                die!(b"--setenv takes two arguments\0" as *const u8 as *const libc::c_char);
            }
            xsetenv(
                *argv.offset(1 as libc::c_int as isize),
                *argv.offset(2 as libc::c_int as isize),
                1 as libc::c_int,
            );
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--unsetenv\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--unsetenv takes an argument\0" as *const u8 as *const libc::c_char);
            }
            xunsetenv(*argv.offset(1 as libc::c_int as isize));
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--uid\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            let mut the_uid: libc::c_int = 0;
            let mut endptr_14 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--uid takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_sandbox_uid != -(1 as libc::c_int) as uid_t {
                warn_only_last_option(b"--uid\0" as *const u8 as *const libc::c_char);
            }
            the_uid = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_14,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_14.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_uid < 0 as libc::c_int
            {
                die!(
                    b"Invalid uid: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_sandbox_uid = the_uid as uid_t;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--gid\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            let mut the_gid: libc::c_int = 0;
            let mut endptr_15 = 0 as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--gid takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if opt_sandbox_gid != -(1 as libc::c_int) as gid_t {
                warn_only_last_option(b"--gid\0" as *const u8 as *const libc::c_char);
            }
            the_gid = strtol(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_15,
                10 as libc::c_int,
            ) as libc::c_int;
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == 0 as libc::c_int
                || *endptr_15.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                || the_gid < 0 as libc::c_int
            {
                die!(
                    b"Invalid gid: %s\0" as *const u8 as *const libc::c_char,
                    *argv.offset(1 as libc::c_int as isize),
                );
            }
            opt_sandbox_gid = the_gid as gid_t;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--hostname\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if argc < 2 as libc::c_int {
                die!(b"--hostname takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if !opt_sandbox_hostname.is_null() {
                warn_only_last_option(b"--hostname\0" as *const u8 as *const libc::c_char);
            }
            op = setup_op_new(SETUP_SET_HOSTNAME);
            (*op).dest = *argv.offset(1 as libc::c_int as isize);
            (*op).flags = NO_CREATE_DEST;
            opt_sandbox_hostname = *argv.offset(1 as libc::c_int as isize);
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--new-session\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            opt_new_session = true;
        } else if strcmp(
            arg,
            b"--die-with-parent\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            opt_die_with_parent = true;
        } else if strcmp(arg, b"--as-pid-1\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            opt_as_pid_1 = true;
        } else if strcmp(arg, b"--cap-add\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut cap: cap_value_t = 0;
            if argc < 2 as libc::c_int {
                die!(b"--cap-add takes an argument\0" as *const u8 as *const libc::c_char);
            }
            opt_cap_add_or_drop_used = true;
            if strcasecmp(
                *argv.offset(1 as libc::c_int as isize),
                b"ALL\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
            {
                requested_caps[1 as libc::c_int as usize] = 0xffffffff as libc::c_uint;
                requested_caps[0 as libc::c_int as usize] =
                    requested_caps[1 as libc::c_int as usize];
            } else {
                if cap_from_name(*argv.offset(1 as libc::c_int as isize), &mut cap)
                    < 0 as libc::c_int
                {
                    die!(
                        b"unknown cap: %s\0" as *const u8 as *const libc::c_char,
                        *argv.offset(1 as libc::c_int as isize),
                    );
                }
                if cap < 32 as libc::c_int {
                    requested_caps[0 as libc::c_int as usize] =
                        (requested_caps[0 as libc::c_int as usize] as libc::c_long
                            | (1 as libc::c_long) << (cap & 31 as libc::c_int))
                            as u32;
                } else {
                    requested_caps[1 as libc::c_int as usize] =
                        (requested_caps[1 as libc::c_int as usize] as libc::c_long
                            | (1 as libc::c_long)
                                << (cap - 32 as libc::c_int - 32 as libc::c_int
                                    & 31 as libc::c_int)) as u32;
                }
            }
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--cap-drop\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            let mut cap_0: cap_value_t = 0;
            if argc < 2 as libc::c_int {
                die!(b"--cap-drop takes an argument\0" as *const u8 as *const libc::c_char);
            }
            opt_cap_add_or_drop_used = true;
            if strcasecmp(
                *argv.offset(1 as libc::c_int as isize),
                b"ALL\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
            {
                requested_caps[1 as libc::c_int as usize] = 0 as libc::c_int as u32;
                requested_caps[0 as libc::c_int as usize] =
                    requested_caps[1 as libc::c_int as usize];
            } else {
                if cap_from_name(*argv.offset(1 as libc::c_int as isize), &mut cap_0)
                    < 0 as libc::c_int
                {
                    die!(
                        b"unknown cap: %s\0" as *const u8 as *const libc::c_char,
                        *argv.offset(1 as libc::c_int as isize),
                    );
                }
                if cap_0 < 32 as libc::c_int {
                    requested_caps[0 as libc::c_int as usize] =
                        (requested_caps[0 as libc::c_int as usize] as libc::c_long
                            & !((1 as libc::c_long) << (cap_0 & 31 as libc::c_int)))
                            as u32;
                } else {
                    requested_caps[1 as libc::c_int as usize] =
                        (requested_caps[1 as libc::c_int as usize] as libc::c_long
                            & !((1 as libc::c_long)
                                << (cap_0 - 32 as libc::c_int - 32 as libc::c_int
                                    & 31 as libc::c_int))) as u32;
                }
            }
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--perms\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            let mut perms: libc::c_ulong = 0;
            let mut endptr_16 = std::ptr::null_mut() as *mut libc::c_char;
            if argc < 2 as libc::c_int {
                die!(b"--perms takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if next_perms != -(1 as libc::c_int) {
                die!(
                    b"--perms given twice for the same action\0" as *const u8
                        as *const libc::c_char
                );
            }
            perms = strtoul(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_16,
                8 as libc::c_int,
            );
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == '\0' as i32
                || endptr_16.is_null()
                || *endptr_16 as libc::c_int != '\0' as i32
                || perms > 0o7777 as libc::c_int as libc::c_ulong
            {
                die!(
                    b"--perms takes an octal argument <= 07777\0" as *const u8
                        as *const libc::c_char
                );
            }
            next_perms = perms as libc::c_int;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--size\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            let mut size: libc::c_ulonglong = 0;
            let mut endptr_17 = std::ptr::null_mut() as *mut libc::c_char;
            if is_privileged {
                die!(
                    b"The --size option is not permitted in setuid mode\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if argc < 2 as libc::c_int {
                die!(b"--size takes an argument\0" as *const u8 as *const libc::c_char);
            }
            if next_size_arg != 0 {
                die!(
                    b"--size given twice for the same action\0" as *const u8 as *const libc::c_char
                );
            }
            errno!() = 0 as libc::c_int;
            size = strtoull(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_17,
                0 as libc::c_int,
            );
            if errno!() != 0 as libc::c_int
                || *(*__ctype_b_loc()).offset(
                    *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                        as libc::c_int as isize,
                ) as libc::c_int
                    & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
                    == 0
                || endptr_17.is_null()
                || *endptr_17 as libc::c_int != '\0' as i32
                || size == 0 as libc::c_int as libc::c_ulonglong
            {
                die!(
                    b"--size takes a non-zero number of bytes\0" as *const u8
                        as *const libc::c_char
                );
            }
            if size > MAX_TMPFS_BYTES as libc::c_ulonglong {
                die!(
                    b"--size (for tmpfs) is limited to %zu\0" as *const u8 as *const libc::c_char,
                    MAX_TMPFS_BYTES,
                );
            }
            next_size_arg = size as size_t;
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
        } else if strcmp(arg, b"--chmod\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            let mut perms_0: libc::c_ulong = 0;
            let mut endptr_18 = std::ptr::null_mut() as *mut libc::c_char;
            if argc < 3 as libc::c_int {
                die!(b"--chmod takes two arguments\0" as *const u8 as *const libc::c_char);
            }
            perms_0 = strtoul(
                *argv.offset(1 as libc::c_int as isize),
                &mut endptr_18,
                8 as libc::c_int,
            );
            if *(*argv.offset(1 as libc::c_int as isize)).offset(0 as libc::c_int as isize)
                as libc::c_int
                == '\0' as i32
                || endptr_18.is_null()
                || *endptr_18 as libc::c_int != '\0' as i32
                || perms_0 > 0o7777 as libc::c_int as libc::c_ulong
            {
                die!(
                    b"--chmod takes an octal argument <= 07777\0" as *const u8
                        as *const libc::c_char
                );
            }
            op = setup_op_new(SETUP_CHMOD);
            (*op).flags = NO_CREATE_DEST;
            (*op).perms = perms_0 as libc::c_int;
            (*op).dest = *argv.offset(2 as libc::c_int as isize);
            argv = argv.offset(2 as libc::c_int as isize);
            argc -= 2 as libc::c_int;
        } else if strcmp(arg, b"--\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            argv = argv.offset(1 as libc::c_int as isize);
            argc -= 1 as libc::c_int;
            break;
        } else {
            if !(*arg as libc::c_int == '-' as i32) {
                break;
            }
            die!(
                b"Unknown option %s\0" as *const u8 as *const libc::c_char,
                arg,
            );
        }
        if is_modifier_option(arg) == 0 && next_perms >= 0 as libc::c_int {
            die!(
                b"--perms must be followed by an option that creates a file\0" as *const u8
                    as *const libc::c_char,
            );
        }
        if is_modifier_option(arg) == 0 && next_size_arg != 0 {
            die!(b"--size must be followed by --tmpfs\0" as *const u8 as *const libc::c_char);
        }
        if strcmp(arg, b"--overlay-src\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int
            && next_overlay_src_count > 0 as libc::c_int
        {
            die!(
                b"--overlay-src must be followed by another --overlay-src or one of --overlay, --tmp-overlay, or --ro-overlay\0"
                    as *const u8 as *const libc::c_char,
            );
        }
        argv = argv.offset(1);
        argc -= 1;
    }
    *argcp = argc;
    *argvp = argv;
}

unsafe fn parse_args(mut argcp: *mut libc::c_int, mut argvp: *mut *mut *const libc::c_char) {
    let mut total_parsed_argc = *argcp;
    parse_args_recurse(argcp, argvp, false, &mut total_parsed_argc);
    if next_overlay_src_count > 0 as libc::c_int {
        die!(
            b"--overlay-src must be followed by another --overlay-src or one of --overlay, --tmp-overlay, or --ro-overlay\0"
                as *const u8 as *const libc::c_char,
        );
    }
}

unsafe fn read_overflowids() {
    let mut uid_data = std::ptr::null_mut() as *mut libc::c_char;
    let mut gid_data = std::ptr::null_mut() as *mut libc::c_char;
    uid_data = load_file_at(
        AT_FDCWD,
        b"/proc/sys/kernel/overflowuid\0" as *const u8 as *const libc::c_char,
    );
    if uid_data.is_null() {
        die_with_error!(
            b"Can't read /proc/sys/kernel/overflowuid\0" as *const u8 as *const libc::c_char,
        );
    }
    overflow_uid = strtol(
        uid_data,
        std::ptr::null_mut() as *mut *mut libc::c_char,
        10 as libc::c_int,
    ) as uid_t;
    if overflow_uid == 0 as libc::c_int as libc::c_uint {
        die!(b"Can't parse /proc/sys/kernel/overflowuid\0" as *const u8 as *const libc::c_char);
    }
    gid_data = load_file_at(
        AT_FDCWD,
        b"/proc/sys/kernel/overflowgid\0" as *const u8 as *const libc::c_char,
    );
    if gid_data.is_null() {
        die_with_error!(
            b"Can't read /proc/sys/kernel/overflowgid\0" as *const u8 as *const libc::c_char,
        );
    }
    overflow_gid = strtol(
        gid_data,
        std::ptr::null_mut() as *mut *mut libc::c_char,
        10 as libc::c_int,
    ) as gid_t;
    if overflow_gid == 0 as libc::c_int as libc::c_uint {
        die!(b"Can't parse /proc/sys/kernel/overflowgid\0" as *const u8 as *const libc::c_char);
    }
}

unsafe fn namespace_ids_read(mut pid: pid_t) {
    let mut dir = std::ptr::null_mut() as *mut libc::c_char;
    let mut ns_fd = -(1 as libc::c_int);
    let mut info = 0 as *mut NsInfo;
    dir = xasprintf(b"%d/ns\0" as *const u8 as *const libc::c_char, pid);
    ns_fd = ({
        let mut __result: libc::c_long = 0;
        loop {
            __result = openat(proc_fd, dir, 0o10000000 as libc::c_int) as libc::c_long;
            if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                break;
            }
        }
        __result
    }) as libc::c_int;
    if ns_fd < 0 as libc::c_int {
        die_with_error!(
            b"open /proc/%s/ns failed\0" as *const u8 as *const libc::c_char,
            dir,
        );
    }
    info = ns_infos.as_mut_ptr();
    while !((*info).name).is_null() {
        let mut do_unshare = (*info).do_unshare;
        let mut st = std::mem::zeroed();
        let mut r: libc::c_int = 0;
        if !(!do_unshare.is_null() && *do_unshare as bool == false) {
            r = fstatat(ns_fd, (*info).name, &mut st, 0 as libc::c_int);
            if !(r != 0 as libc::c_int) {
                (*info).id = st.st_ino;
            }
        }
        info = info.offset(1);
    }
}

unsafe fn namespace_ids_write(mut fd: libc::c_int, mut in_json: bool) {
    let mut info = 0 as *mut NsInfo;
    info = ns_infos.as_mut_ptr();
    while !((*info).name).is_null() {
        let mut output = std::ptr::null_mut() as *mut libc::c_char;
        let mut indent = 0 as *const libc::c_char;
        let mut nsid: uintmax_t = 0;
        nsid = (*info).id;
        if !(nsid == 0 as libc::c_int as libc::c_ulong) {
            indent = if in_json as libc::c_int != 0 {
                b" \0" as *const u8 as *const libc::c_char
            } else {
                b"\n    \0" as *const u8 as *const libc::c_char
            };
            output = xasprintf(
                b",%s\"%s-namespace\": %ju\0" as *const u8 as *const libc::c_char,
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
    let mut event_fd = -(1 as libc::c_int);
    let mut child_wait_fd = -(1 as libc::c_int);
    let mut setup_finished_pipe: [libc::c_int; 2] = [-(1 as libc::c_int), -(1 as libc::c_int)];
    let mut new_cwd = 0 as *const libc::c_char;
    let mut ns_uid: uid_t = 0;
    let mut ns_gid: gid_t = 0;
    let mut sbuf = std::mem::zeroed();
    let mut val: u64 = 0;
    let mut res: libc::c_int = 0;
    let mut args_data = std::ptr::null_mut() as *mut libc::c_char;
    let mut intermediate_pids_sockets: [libc::c_int; 2] =
        [-(1 as libc::c_int), -(1 as libc::c_int)];
    let mut exec_path = std::ptr::null_mut() as *const libc::c_char;
    let mut i: libc::c_int = 0;
    if argc == 2 as libc::c_int
        && strcmp(
            *argv.offset(1 as libc::c_int as isize),
            b"--version\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
    {
        print_version_and_exit();
    }
    real_uid = getuid();
    real_gid = getgid();
    acquire_privs();
    if prctl(
        PR_SET_NO_NEW_PRIVS,
        1 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int,
    ) < 0 as libc::c_int
    {
        die_with_error!(b"prctl(PR_SET_NO_NEW_PRIVS) failed\0" as *const u8 as *const libc::c_char);
    }
    read_overflowids();
    argv0 = *argv.offset(0 as libc::c_int as isize);
    if isatty(1 as libc::c_int) != 0 {
        host_tty_dev = ttyname(1 as libc::c_int);
    }
    argv = argv.offset(1);
    argc -= 1;
    if argc <= 0 as libc::c_int {
        usage(EXIT_FAILURE, stderr);
    }
    parse_args(
        &mut argc,
        &mut argv as *mut *mut *mut libc::c_char as *mut *mut *const libc::c_char,
    );
    args_data = opt_args_data;
    opt_args_data = std::ptr::null_mut() as *mut libc::c_char;
    if (requested_caps[0 as libc::c_int as usize] != 0
        || requested_caps[1 as libc::c_int as usize] != 0)
        && is_privileged as libc::c_int != 0
    {
        die!(
            b"--cap-add in setuid mode can be used only by root\0" as *const u8
                as *const libc::c_char,
        );
    }
    if opt_userns_block_fd != -(1 as libc::c_int) && !opt_unshare_user {
        die!(b"--userns-block-fd requires --unshare-user\0" as *const u8 as *const libc::c_char);
    }
    if opt_userns_block_fd != -(1 as libc::c_int) && opt_info_fd == -(1 as libc::c_int) {
        die!(b"--userns-block-fd requires --info-fd\0" as *const u8 as *const libc::c_char);
    }
    if opt_userns_fd != -(1 as libc::c_int) && opt_unshare_user as libc::c_int != 0 {
        die!(b"--userns not compatible --unshare-user\0" as *const u8 as *const libc::c_char);
    }
    if opt_userns_fd != -(1 as libc::c_int) && opt_unshare_user_try as libc::c_int != 0 {
        die!(b"--userns not compatible --unshare-user-try\0" as *const u8 as *const libc::c_char);
    }
    if opt_disable_userns as libc::c_int != 0 && !opt_unshare_user {
        die!(b"--disable-userns requires --unshare-user\0" as *const u8 as *const libc::c_char);
    }
    if opt_disable_userns as libc::c_int != 0 && opt_userns_block_fd != -(1 as libc::c_int) {
        die!(
            b"--disable-userns is not compatible with  --userns-block-fd\0" as *const u8
                as *const libc::c_char,
        );
    }
    if opt_userns_fd != -(1 as libc::c_int) && is_privileged as libc::c_int != 0 {
        die!(b"--userns doesn't work in setuid mode\0" as *const u8 as *const libc::c_char);
    }
    if opt_userns2_fd != -(1 as libc::c_int) && is_privileged as libc::c_int != 0 {
        die!(b"--userns2 doesn't work in setuid mode\0" as *const u8 as *const libc::c_char);
    }
    if !is_privileged
        && getuid() != 0 as libc::c_int as libc::c_uint
        && opt_userns_fd == -(1 as libc::c_int)
    {
        opt_unshare_user = true;
    }
    if opt_unshare_user_try as libc::c_int != 0
        && stat(
            b"/proc/self/ns/user\0" as *const u8 as *const libc::c_char,
            &mut sbuf,
        ) == 0 as libc::c_int
    {
        let mut disabled = false;
        if stat(
            b"/sys/module/user_namespace/parameters/enable\0" as *const u8 as *const libc::c_char,
            &mut sbuf,
        ) == 0 as libc::c_int
        {
            let mut enable = std::ptr::null_mut() as *mut libc::c_char;
            enable = load_file_at(
                AT_FDCWD,
                b"/sys/module/user_namespace/parameters/enable\0" as *const u8
                    as *const libc::c_char,
            );
            if !enable.is_null()
                && *enable.offset(0 as libc::c_int as isize) as libc::c_int == 'N' as i32
            {
                disabled = true;
            }
        }
        if stat(
            b"/proc/sys/user/max_user_namespaces\0" as *const u8 as *const libc::c_char,
            &mut sbuf,
        ) == 0 as libc::c_int
        {
            let mut max_user_ns = std::ptr::null_mut() as *mut libc::c_char;
            max_user_ns = load_file_at(
                AT_FDCWD,
                b"/proc/sys/user/max_user_namespaces\0" as *const u8 as *const libc::c_char,
            );
            if !max_user_ns.is_null()
                && strcmp(max_user_ns, b"0\n\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                disabled = true;
            }
        }
        if !disabled {
            opt_unshare_user = true;
        }
    }
    if argc <= 0 as libc::c_int {
        usage(EXIT_FAILURE, stderr);
    }
    if opt_sandbox_uid == -(1 as libc::c_int) as uid_t {
        opt_sandbox_uid = real_uid;
    }
    if opt_sandbox_gid == -(1 as libc::c_int) as gid_t {
        opt_sandbox_gid = real_gid;
    }
    if !opt_unshare_user && opt_userns_fd == -(1 as libc::c_int) && opt_sandbox_uid != real_uid {
        die!(
            b"Specifying --uid requires --unshare-user or --userns\0" as *const u8
                as *const libc::c_char,
        );
    }
    if !opt_unshare_user && opt_userns_fd == -(1 as libc::c_int) && opt_sandbox_gid != real_gid {
        die!(
            b"Specifying --gid requires --unshare-user or --userns\0" as *const u8
                as *const libc::c_char,
        );
    }
    if !opt_unshare_uts && !opt_sandbox_hostname.is_null() {
        die!(b"Specifying --hostname requires --unshare-uts\0" as *const u8 as *const libc::c_char);
    }
    if opt_as_pid_1 as libc::c_int != 0 && !opt_unshare_pid {
        die!(b"Specifying --as-pid-1 requires --unshare-pid\0" as *const u8 as *const libc::c_char);
    }
    if opt_as_pid_1 as libc::c_int != 0 && !lock_files.is_null() {
        die!(
            b"Specifying --as-pid-1 and --lock-file is not permitted\0" as *const u8
                as *const libc::c_char,
        );
    }
    proc_fd = ({
        let mut __result: libc::c_long = 0;
        loop {
            __result = open(
                b"/proc\0" as *const u8 as *const libc::c_char,
                0o10000000 as libc::c_int,
            ) as libc::c_long;
            if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                break;
            }
        }
        __result
    }) as libc::c_int;
    if proc_fd == -(1 as libc::c_int) {
        die_with_error!(b"Can't open /proc\0" as *const u8 as *const libc::c_char);
    }
    base_path = b"/tmp\0" as *const u8 as *const libc::c_char;
    if opt_unshare_pid as libc::c_int != 0 && !opt_as_pid_1 {
        event_fd = eventfd(0 as libc::c_int as libc::c_uint, EFD_CLOEXEC | EFD_NONBLOCK);
        if event_fd == -(1 as libc::c_int) {
            die_with_error!(b"eventfd()\0" as *const u8 as *const libc::c_char);
        }
    }
    block_sigchild();
    clone_flags = SIGCHLD | CLONE_NEWNS;
    if opt_unshare_user {
        clone_flags |= CLONE_NEWUSER;
    }
    if opt_unshare_pid as libc::c_int != 0 && opt_pidns_fd == -(1 as libc::c_int) {
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
        if stat(
            b"/proc/self/ns/cgroup\0" as *const u8 as *const libc::c_char,
            &mut sbuf,
        ) != 0
        {
            if errno!() == ENOENT {
                die!(
                    b"Cannot create new cgroup namespace because the kernel does not support it\0"
                        as *const u8 as *const libc::c_char,
                );
            } else {
                die_with_error!(
                    b"stat on /proc/self/ns/cgroup failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        clone_flags |= CLONE_NEWCGROUP;
    }
    if opt_unshare_cgroup_try {
        opt_unshare_cgroup = stat(
            b"/proc/self/ns/cgroup\0" as *const u8 as *const libc::c_char,
            &mut sbuf,
        ) == 0;
        if opt_unshare_cgroup {
            clone_flags |= CLONE_NEWCGROUP;
        }
    }
    child_wait_fd = eventfd(0 as libc::c_int as libc::c_uint, EFD_CLOEXEC);
    if child_wait_fd == -(1 as libc::c_int) {
        die_with_error!(b"eventfd()\0" as *const u8 as *const libc::c_char);
    }
    if opt_json_status_fd != -(1 as libc::c_int) {
        let mut ret: libc::c_int = 0;
        ret = pipe2(setup_finished_pipe.as_mut_ptr(), O_CLOEXEC);
        if ret == -(1 as libc::c_int) {
            die_with_error!(b"pipe2()\0" as *const u8 as *const libc::c_char);
        }
    }
    if opt_userns_fd > 0 as libc::c_int && setns(opt_userns_fd, CLONE_NEWUSER) != 0 as libc::c_int {
        if errno!() == EINVAL {
            die!(
                b"Joining the specified user namespace failed, it might not be a descendant of the current user namespace.\0"
                    as *const u8 as *const libc::c_char,
            );
        }
        die_with_error!(
            b"Joining specified user namespace failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if opt_pidns_fd != -(1 as libc::c_int) {
        prctl(
            PR_SET_CHILD_SUBREAPER,
            1 as libc::c_int,
            0 as libc::c_int,
            0 as libc::c_int,
            0 as libc::c_int,
        );
        create_pid_socketpair(intermediate_pids_sockets.as_mut_ptr());
    }
    pid = raw_clone(clone_flags as libc::c_ulong, std::ptr::null_mut());
    if pid == -(1 as libc::c_int) {
        if opt_unshare_user {
            if errno!() == EINVAL {
                die!(
                    b"Creating new namespace failed, likely because the kernel does not support user namespaces.  bwrap must be installed setuid on such systems.\0"
                        as *const u8 as *const libc::c_char,
                );
            } else if errno!() == EPERM && !is_privileged {
                die!(
                    b"No permissions to creating new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'.\0"
                        as *const u8 as *const libc::c_char,
                );
            }
        }
        if errno!() == ENOSPC {
            die!(
                b"Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)\0"
                    as *const u8 as *const libc::c_char,
            );
        }
        die_with_error!(b"Creating new namespace failed\0" as *const u8 as *const libc::c_char);
    }
    ns_uid = opt_sandbox_uid;
    ns_gid = opt_sandbox_gid;
    if pid != 0 as libc::c_int {
        if intermediate_pids_sockets[0 as libc::c_int as usize] != -(1 as libc::c_int) {
            close(intermediate_pids_sockets[1 as libc::c_int as usize]);
            pid = read_pid_from_socket(intermediate_pids_sockets[0 as libc::c_int as usize]);
            close(intermediate_pids_sockets[0 as libc::c_int as usize]);
        }
        namespace_ids_read(pid);
        if is_privileged as libc::c_int != 0
            && opt_unshare_user as libc::c_int != 0
            && opt_userns_block_fd == -(1 as libc::c_int)
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
        if opt_userns2_fd > 0 as libc::c_int
            && setns(opt_userns2_fd, CLONE_NEWUSER) != 0 as libc::c_int
        {
            die_with_error!(b"Setting userns2 failed\0" as *const u8 as *const libc::c_char);
        }
        drop_privs(false, false);
        handle_die_with_parent();
        if opt_info_fd != -(1 as libc::c_int) {
            let mut output = xasprintf(
                b"{\n    \"child-pid\": %i\0" as *const u8 as *const libc::c_char,
                pid,
            );
            dump_info(opt_info_fd, output, true);
            namespace_ids_write(opt_info_fd, false);
            dump_info(
                opt_info_fd,
                b"\n}\n\0" as *const u8 as *const libc::c_char,
                true,
            );
            close(opt_info_fd);
        }
        if opt_json_status_fd != -(1 as libc::c_int) {
            let mut output_0 = xasprintf(
                b"{ \"child-pid\": %i\0" as *const u8 as *const libc::c_char,
                pid,
            );
            dump_info(opt_json_status_fd, output_0, true);
            namespace_ids_write(opt_json_status_fd, true);
            dump_info(
                opt_json_status_fd,
                b" }\n\0" as *const u8 as *const libc::c_char,
                true,
            );
        }
        if opt_userns_block_fd != -(1 as libc::c_int) {
            let mut b: [libc::c_char; 1] = [0; 1];
            ({
                loop {
                    let __result = read(
                        opt_userns_block_fd,
                        b.as_mut_ptr() as *mut libc::c_void,
                        1 as libc::c_int as size_t,
                    );
                    if !(__result == -(1) && errno!() == EINTR) {
                        break __result;
                    }
                }
            });
            ({
                loop {
                    let __result = read(
                        opt_userns_block_fd,
                        b.as_mut_ptr() as *mut libc::c_void,
                        1 as libc::c_int as size_t,
                    );
                    if !(__result == -(1) && errno!() == EINTR) {
                        break __result;
                    }
                }
            });
            close(opt_userns_block_fd);
        }
        val = 1 as libc::c_int as u64;
        res = ({
            loop {
                let __result = write(
                    child_wait_fd,
                    &mut val as *mut u64 as *const libc::c_void,
                    8 as libc::c_int as size_t,
                );
                if !(__result == -(1) && errno!() == EINTR) {
                    break __result;
                }
            }
        }) as libc::c_int;
        close(child_wait_fd);
        return monitor_child(
            event_fd,
            pid,
            setup_finished_pipe[0 as libc::c_int as usize],
        );
    }
    if opt_pidns_fd > 0 as libc::c_int {
        if setns(opt_pidns_fd, CLONE_NEWPID) != 0 as libc::c_int {
            die_with_error!(b"Setting pidns failed\0" as *const u8 as *const libc::c_char);
        }
        fork_intermediate_child();
        if opt_unshare_pid {
            if unshare(CLONE_NEWPID) != 0 {
                die_with_error!(b"unshare pid ns\0" as *const u8 as *const libc::c_char);
            }
            fork_intermediate_child();
        }
        close(intermediate_pids_sockets[0 as libc::c_int as usize]);
        send_pid_on_socket(intermediate_pids_sockets[1 as libc::c_int as usize]);
        close(intermediate_pids_sockets[1 as libc::c_int as usize]);
    }
    if opt_info_fd != -(1 as libc::c_int) {
        close(opt_info_fd);
    }
    if opt_json_status_fd != -(1 as libc::c_int) {
        close(opt_json_status_fd);
    }
    res = read(
        child_wait_fd,
        &mut val as *mut u64 as *mut libc::c_void,
        8 as libc::c_int as size_t,
    ) as libc::c_int;
    close(child_wait_fd);
    switch_to_user_with_privs();
    if opt_unshare_net {
        loopback_setup();
    }
    ns_uid = opt_sandbox_uid;
    ns_gid = opt_sandbox_gid;
    if !is_privileged
        && opt_unshare_user as libc::c_int != 0
        && opt_userns_block_fd == -(1 as libc::c_int)
    {
        if opt_needs_devpts {
            ns_uid = 0 as libc::c_int as uid_t;
            ns_gid = 0 as libc::c_int as gid_t;
        }
        write_uid_gid_map(
            ns_uid,
            real_uid,
            ns_gid,
            real_gid,
            -(1 as libc::c_int),
            true,
            false,
        );
    }
    old_umask = umask(0 as libc::c_int as mode_t);
    resolve_symlinks_in_ops();
    if mount(
        std::ptr::null_mut() as *const libc::c_char,
        b"/\0" as *const u8 as *const libc::c_char,
        std::ptr::null_mut() as *const libc::c_char,
        (MS_SILENT | MS_SLAVE | MS_REC) as libc::c_ulong,
        std::ptr::null_mut() as *const libc::c_void,
    ) < 0 as libc::c_int
    {
        die_with_mount_error!(b"Failed to make / slave\0" as *const u8 as *const libc::c_char);
    }
    if mount(
        b"tmpfs\0" as *const u8 as *const libc::c_char,
        base_path,
        b"tmpfs\0" as *const u8 as *const libc::c_char,
        (MS_NODEV | MS_NOSUID) as libc::c_ulong,
        std::ptr::null_mut() as *const libc::c_void,
    ) != 0 as libc::c_int
    {
        die_with_mount_error!(b"Failed to mount tmpfs\0" as *const u8 as *const libc::c_char);
    }
    old_cwd = get_current_dir_name();
    if chdir(base_path) != 0 as libc::c_int {
        die_with_error!(b"chdir base_path\0" as *const u8 as *const libc::c_char);
    }
    if mkdir(
        b"newroot\0" as *const u8 as *const libc::c_char,
        0o755 as libc::c_int as mode_t,
    ) != 0
    {
        die_with_error!(b"Creating newroot failed\0" as *const u8 as *const libc::c_char);
    }
    if mount(
        b"newroot\0" as *const u8 as *const libc::c_char,
        b"newroot\0" as *const u8 as *const libc::c_char,
        std::ptr::null_mut() as *const libc::c_char,
        (MS_SILENT as libc::c_uint
            | MS_MGC_VAL as libc::c_uint
            | MS_BIND as libc::c_uint
            | MS_REC as libc::c_uint) as libc::c_ulong,
        std::ptr::null_mut() as *const libc::c_void,
    ) < 0 as libc::c_int
    {
        die_with_mount_error!(b"setting up newroot bind\0" as *const u8 as *const libc::c_char);
    }
    if mkdir(
        b"oldroot\0" as *const u8 as *const libc::c_char,
        0o755 as libc::c_int as mode_t,
    ) != 0
    {
        die_with_error!(b"Creating oldroot failed\0" as *const u8 as *const libc::c_char);
    }
    i = 0 as libc::c_int;
    while i < opt_tmp_overlay_count {
        let mut dirname = 0 as *mut libc::c_char;
        dirname = xasprintf(
            b"tmp-overlay-upper-%d\0" as *const u8 as *const libc::c_char,
            i,
        );
        if mkdir(dirname, 0o755 as libc::c_int as mode_t) != 0 {
            die_with_error!(
                b"Creating --tmp-overlay upperdir failed\0" as *const u8 as *const libc::c_char,
            );
        }
        free(dirname as *mut libc::c_void);
        dirname = xasprintf(
            b"tmp-overlay-work-%d\0" as *const u8 as *const libc::c_char,
            i,
        );
        if mkdir(dirname, 0o755 as libc::c_int as mode_t) != 0 {
            die_with_error!(
                b"Creating --tmp-overlay workdir failed\0" as *const u8 as *const libc::c_char,
            );
        }
        free(dirname as *mut libc::c_void);
        i += 1;
    }
    if pivot_root(base_path, b"oldroot\0" as *const u8 as *const libc::c_char) != 0 {
        die_with_error!(b"pivot_root\0" as *const u8 as *const libc::c_char);
    }
    if chdir(b"/\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int {
        die_with_error!(b"chdir / (base path)\0" as *const u8 as *const libc::c_char);
    }
    if is_privileged {
        let mut child: pid_t = 0;
        let mut privsep_sockets: [libc::c_int; 2] = [0; 2];
        if socketpair(
            AF_UNIX,
            SOCK_SEQPACKET | SOCK_CLOEXEC,
            0 as libc::c_int,
            privsep_sockets.as_mut_ptr(),
        ) != 0 as libc::c_int
        {
            die_with_error!(b"Can't create privsep socket\0" as *const u8 as *const libc::c_char);
        }
        child = fork();
        if child == -(1 as libc::c_int) {
            die_with_error!(
                b"Can't fork unprivileged helper\0" as *const u8 as *const libc::c_char
            );
        }
        if child == 0 as libc::c_int {
            drop_privs(false, true);
            close(privsep_sockets[0 as libc::c_int as usize]);
            setup_newroot(opt_unshare_pid, privsep_sockets[1 as libc::c_int as usize]);
            exit(0 as libc::c_int);
        } else {
            let mut status: libc::c_int = 0;
            let mut buffer: [u32; 2048] = [0; 2048];
            let mut op: u32 = 0;
            let mut flags: u32 = 0;
            let mut perms: u32 = 0;
            let mut size_arg: size_t = 0;
            let mut arg1 = 0 as *const libc::c_char;
            let mut arg2 = 0 as *const libc::c_char;
            let mut unpriv_socket = -(1 as libc::c_int);
            unpriv_socket = privsep_sockets[0 as libc::c_int as usize];
            close(privsep_sockets[1 as libc::c_int as usize]);
            loop {
                op = read_priv_sec_op(
                    unpriv_socket,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    ::core::mem::size_of::<[u32; 2048]>(),
                    &mut flags,
                    &mut perms,
                    &mut size_arg,
                    &mut arg1,
                    &mut arg2,
                );
                privileged_op(-(1 as libc::c_int), op, flags, perms, size_arg, arg1, arg2);
                if ({
                    loop {
                        let __result =
                            write(unpriv_socket, buffer.as_mut_ptr() as *const libc::c_void, 1);
                        if !(__result == -(1) && errno!() == EINTR) {
                            break __result;
                        }
                    }
                }) != 1
                {
                    die!(b"Can't write to op_socket\0" as *const u8 as *const libc::c_char);
                }
                if !(op != PRIV_SEP_OP_DONE as libc::c_int as libc::c_uint) {
                    break;
                }
            }
            let mut __result: libc::c_long = 0;
            loop {
                __result = waitpid(child, &mut status, 0 as libc::c_int) as libc::c_long;
                if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                    break;
                }
            }
        }
    } else {
        setup_newroot(opt_unshare_pid, -(1 as libc::c_int));
    }
    close_ops_fd();
    if mount(
        b"oldroot\0" as *const u8 as *const libc::c_char,
        b"oldroot\0" as *const u8 as *const libc::c_char,
        std::ptr::null_mut() as *const libc::c_char,
        (MS_SILENT | MS_REC | MS_PRIVATE) as libc::c_ulong,
        std::ptr::null_mut() as *const libc::c_void,
    ) != 0 as libc::c_int
    {
        die_with_mount_error!(
            b"Failed to make old root rprivate\0" as *const u8 as *const libc::c_char,
        );
    }
    if umount2(b"oldroot\0" as *const u8 as *const libc::c_char, MNT_DETACH) != 0 {
        die_with_error!(b"unmount old root\0" as *const u8 as *const libc::c_char);
    }
    let mut oldrootfd = ({
        let mut __result_0: libc::c_long = 0;
        loop {
            __result_0 = open(
                b"/\0" as *const u8 as *const libc::c_char,
                0o200000 as libc::c_int | 0 as libc::c_int,
            ) as libc::c_long;
            if !(__result_0 == -(1 as libc::c_long) && errno!() == EINTR) {
                break;
            }
        }
        __result_0
    }) as libc::c_int;
    if oldrootfd < 0 as libc::c_int {
        die_with_error!(b"can't open /\0" as *const u8 as *const libc::c_char);
    }
    if chdir(b"/newroot\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int {
        die_with_error!(b"chdir /newroot\0" as *const u8 as *const libc::c_char);
    }
    if pivot_root(
        b".\0" as *const u8 as *const libc::c_char,
        b".\0" as *const u8 as *const libc::c_char,
    ) != 0 as libc::c_int
    {
        die_with_error!(b"pivot_root(/newroot)\0" as *const u8 as *const libc::c_char);
    }
    if fchdir(oldrootfd) < 0 as libc::c_int {
        die_with_error!(b"fchdir to oldroot\0" as *const u8 as *const libc::c_char);
    }
    if umount2(b".\0" as *const u8 as *const libc::c_char, MNT_DETACH) < 0 as libc::c_int {
        die_with_error!(b"umount old root\0" as *const u8 as *const libc::c_char);
    }
    if chdir(b"/\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int {
        die_with_error!(b"chdir /\0" as *const u8 as *const libc::c_char);
    }
    if opt_userns2_fd > 0 as libc::c_int && setns(opt_userns2_fd, CLONE_NEWUSER) != 0 as libc::c_int
    {
        die_with_error!(b"Setting userns2 failed\0" as *const u8 as *const libc::c_char);
    }
    if opt_unshare_user as libc::c_int != 0
        && opt_userns_block_fd == -(1 as libc::c_int)
        && (ns_uid != opt_sandbox_uid
            || ns_gid != opt_sandbox_gid
            || opt_disable_userns as libc::c_int != 0)
    {
        if opt_disable_userns {
            let mut sysctl_fd = -(1 as libc::c_int);
            sysctl_fd = ({
                let mut __result_0: libc::c_long = 0;
                loop {
                    __result_0 = openat(
                        proc_fd,
                        b"sys/user/max_user_namespaces\0" as *const u8 as *const libc::c_char,
                        0o1 as libc::c_int,
                    ) as libc::c_long;
                    if !(__result_0 == -(1 as libc::c_long) && errno!() == EINTR) {
                        break;
                    }
                }
                __result_0
            }) as libc::c_int;
            if sysctl_fd < 0 as libc::c_int {
                die_with_error!(
                    b"cannot open /proc/sys/user/max_user_namespaces\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if write_to_fd(
                sysctl_fd,
                b"1\0" as *const u8 as *const libc::c_char,
                1 as libc::c_int as ssize_t,
            ) < 0 as libc::c_int
            {
                die_with_error!(
                    b"sysctl user.max_user_namespaces = 1\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        if unshare(CLONE_NEWUSER) != 0 {
            die_with_error!(b"unshare user ns\0" as *const u8 as *const libc::c_char);
        }
        drop_cap_bounding_set(false);
        write_uid_gid_map(
            opt_sandbox_uid,
            ns_uid,
            opt_sandbox_gid,
            ns_gid,
            -(1 as libc::c_int),
            false,
            false,
        );
    }
    if opt_disable_userns as libc::c_int != 0 || opt_assert_userns_disabled as libc::c_int != 0 {
        res = unshare(CLONE_NEWUSER);
        if res == 0 as libc::c_int {
            die!(
                b"creation of new user namespaces was not disabled as requested\0" as *const u8
                    as *const libc::c_char,
            );
        }
    }
    drop_privs(!is_privileged, true);
    if opt_block_fd != -(1 as libc::c_int) {
        let mut b_0: [libc::c_char; 1] = [0; 1];
        ({
            loop {
                let __result_0 = read(
                    opt_block_fd,
                    b_0.as_mut_ptr() as *mut libc::c_void,
                    1 as libc::c_int as size_t,
                );
                if !(__result_0 == -(1) && errno!() == EINTR) {
                    break __result_0;
                }
            }
        });
        ({
            loop {
                let __result_0 = read(
                    opt_block_fd,
                    b_0.as_mut_ptr() as *mut libc::c_void,
                    1 as libc::c_int as size_t,
                );
                if !(__result_0 == -(1) && errno!() == EINTR) {
                    break __result_0;
                }
            }
        });
        close(opt_block_fd);
    }
    if opt_seccomp_fd != -(1 as libc::c_int) {
        assert!(seccomp_programs.is_null())
    }
    umask(old_umask);
    new_cwd = b"/\0" as *const u8 as *const libc::c_char;
    if !opt_chdir_path.is_null() {
        if chdir(opt_chdir_path) != 0 {
            die_with_error!(
                b"Can't chdir to %s\0" as *const u8 as *const libc::c_char,
                opt_chdir_path,
            );
        }
        new_cwd = opt_chdir_path;
    } else if chdir(old_cwd) == 0 as libc::c_int {
        new_cwd = old_cwd;
    } else {
        let mut home: *const libc::c_char = getenv(b"HOME\0" as *const u8 as *const libc::c_char);
        if !home.is_null() && chdir(home) == 0 as libc::c_int {
            new_cwd = home;
        }
    }
    xsetenv(
        b"PWD\0" as *const u8 as *const libc::c_char,
        new_cwd,
        1 as libc::c_int,
    );
    free(old_cwd as *mut libc::c_void);
    if opt_new_session as libc::c_int != 0 && setsid() == -(1 as libc::c_int) {
        die_with_error!(b"setsid\0" as *const u8 as *const libc::c_char);
    }
    if label_exec(opt_exec_label) == -(1 as libc::c_int) {
        die_with_error!(
            b"label_exec %s\0" as *const u8 as *const libc::c_char,
            *argv.offset(0 as libc::c_int as isize),
        );
    }
    if !opt_as_pid_1
        && (opt_unshare_pid as libc::c_int != 0
            || !lock_files.is_null()
            || opt_sync_fd != -(1 as libc::c_int))
    {
        pid = fork();
        if pid == -(1 as libc::c_int) {
            die_with_error!(b"Can't fork for pid 1\0" as *const u8 as *const libc::c_char);
        }
        if pid != 0 as libc::c_int {
            drop_all_caps(false);
            let mut dont_close: [libc::c_int; 3] = [0; 3];
            let mut j = 0 as libc::c_int;
            if event_fd != -(1 as libc::c_int) {
                let fresh6 = j;
                j = j + 1;
                dont_close[fresh6 as usize] = event_fd;
            }
            if opt_sync_fd != -(1 as libc::c_int) {
                let fresh7 = j;
                j = j + 1;
                dont_close[fresh7 as usize] = opt_sync_fd;
            }
            let fresh8 = j;
            j = j + 1;
            dont_close[fresh8 as usize] = -(1 as libc::c_int);
            fdwalk(
                proc_fd,
                Some(close_extra_fds as unsafe fn(*mut libc::c_void, libc::c_int) -> libc::c_int),
                dont_close.as_mut_ptr() as *mut libc::c_void,
            );
            return do_init(event_fd, pid);
        }
    }
    if proc_fd != -(1 as libc::c_int) {
        close(proc_fd);
    }
    if !opt_as_pid_1 && opt_sync_fd != -(1 as libc::c_int) {
        close(opt_sync_fd);
    }
    unblock_sigchild();
    handle_die_with_parent();
    if !is_privileged {
        set_ambient_capabilities();
    }
    seccomp_programs_apply();
    if setup_finished_pipe[1 as libc::c_int as usize] != -(1 as libc::c_int) {
        let mut data = 0 as libc::c_int as libc::c_char;
        res = write_to_fd(
            setup_finished_pipe[1 as libc::c_int as usize],
            &mut data,
            1 as libc::c_int as ssize_t,
        );
    }
    exec_path = *argv.offset(0 as libc::c_int as isize);
    if !opt_argv0.is_null() {
        let ref mut fresh9 = *argv.offset(0 as libc::c_int as isize);
        *fresh9 = opt_argv0 as *mut libc::c_char;
    }
    if execvp(exec_path, argv as *const *const libc::c_char) == -(1 as libc::c_int) {
        if setup_finished_pipe[1 as libc::c_int as usize] != -(1 as libc::c_int) {
            let mut saved_errno = errno!();
            let mut data_0 = 0 as libc::c_int as libc::c_char;
            res = write_to_fd(
                setup_finished_pipe[1 as libc::c_int as usize],
                &mut data_0,
                1 as libc::c_int as ssize_t,
            );
            errno!() = saved_errno;
        }
        die_with_error!(
            b"execvp %s\0" as *const u8 as *const libc::c_char,
            exec_path,
        );
    }
    return 0 as libc::c_int;
}
