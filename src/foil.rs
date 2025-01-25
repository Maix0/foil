use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::IsTerminal;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;

use ::libc;
use caps::errors::CapsError;
use caps::{Capability, CapsHashSet};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::mount::{MntFlags, MsFlags};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sched::CloneFlags;
use nix::sys::eventfd::EventFd;
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::SfdFlags;
use nix::sys::socket::SockFlag;
use nix::sys::stat::Mode;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::{ForkResult, Gid, Pid, Uid};
use nix::NixPath;
use privilged_op::{PrivilegedOp, PrivilegedOpError};

use crate::setup_newroot::setup_newroot;

use crate::*;
use crate::{
    types::*,
    utils::{
        fdwalk, load_file_data, pivot_root,
        raw_clone, write_to_fd, xcalloc,
    },
};

use crate::privilged_op::privileged_op;

#[derive(Copy, Clone)]
pub struct NsInfo {
    pub name: &'static CStr,
    pub do_unshare: fn(&mut State) -> Option<&mut bool>,
    pub id: fn(&mut State) -> &mut Option<ino_t>,
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct  SetupOpFlag: u32 {
        const ALLOW_NOTEXIST = 1;
        const NO_CREATE_DEST = 2;
    }
}

#[derive(Debug)]
pub enum SetupOp {
    Chmod {
        dest: PathBuf,
        perms: Option<Mode>,
    },
    SetHostname {
        hostname: OsString,
    },
    RemountRoNoRecursive {
        dest: PathBuf,
        perms: Option<Mode>,
    },
    MakeSymlink {
        dest: PathBuf,
        perms: Option<Mode>,
        src: PathBuf,
    },
    MakeRoBindFile {
        dest: PathBuf,
        fd: OwnedFd,
        perms: Option<Mode>,
    },
    MakeBindFile {
        dest: PathBuf,
        fd: OwnedFd,
        perms: Option<Mode>,
    },
    MakeFile {
        dest: PathBuf,
        fd: OwnedFd,
        perms: Option<Mode>,
    },
    MakeDir {
        dest: PathBuf,
        perms: Option<Mode>,
    },
    MountMqueue {
        dest: PathBuf,
        perms: Option<Mode>,
    },
    MountTmpfs {
        dest: PathBuf,
        perms: Option<Mode>,
        size: Option<NonZeroUsize>,
    },
    MountDev {
        dest: PathBuf,
        perms: Option<Mode>,
    },
    MountProc {
        dest: PathBuf,
        perms: Option<Mode>,
    },

    OverlaySrc {
        allow_not_exist: bool,
        src: PathBuf,
    },
    RoOverlayMount {
        dest: PathBuf,
        perms: Option<Mode>,
        src: PathBuf,
    },
    TmpOverlayMount {
        dest: PathBuf,
        perms: Option<Mode>,
    },
    OverlayMount {
        allow_not_exist: bool,
        dest: PathBuf,
        perms: Option<Mode>,
        src: PathBuf,
    },

    DevBindMount {
        allow_not_exist: bool,
        dest: PathBuf,
        perms: Option<Mode>,
        src: PathBuf,
    },
    RoBindMount {
        allow_not_exist: bool,
        dest: PathBuf,
        perms: Option<Mode>,
        src: PathBuf,
    },
    BindMount {
        allow_not_exist: bool,
        dest: PathBuf,
        perms: Option<Mode>,
        src: PathBuf,
    },
}

impl SetupOp {
    pub fn src_mut(&mut self) -> Option<&mut PathBuf> {
        match self {
            SetupOp::OverlaySrc { src, .. }
            | SetupOp::MakeSymlink { src, .. }
            | SetupOp::RoOverlayMount { src, .. }
            | SetupOp::OverlayMount { src, .. }
            | SetupOp::DevBindMount { src, .. }
            | SetupOp::RoBindMount { src, .. }
            | SetupOp::BindMount { src, .. } => Some(src),
            _ => None,
        }
    }

    pub fn src(&self) -> Option<&PathBuf> {
        match self {
            SetupOp::OverlaySrc { src, .. }
            | SetupOp::MakeSymlink { src, .. }
            | SetupOp::RoOverlayMount { src, .. }
            | SetupOp::OverlayMount { src, .. }
            | SetupOp::DevBindMount { src, .. }
            | SetupOp::RoBindMount { src, .. }
            | SetupOp::BindMount { src, .. } => Some(src),
            _ => None,
        }
    }

    pub fn dest(&self) -> Option<&PathBuf> {
        match self {
            SetupOp::Chmod { dest, .. }
            | SetupOp::RemountRoNoRecursive { dest, .. }
            | SetupOp::MakeSymlink { dest, .. }
            | SetupOp::MakeRoBindFile { dest, .. }
            | SetupOp::MakeBindFile { dest, .. }
            | SetupOp::MakeFile { dest, .. }
            | SetupOp::MakeDir { dest, .. }
            | SetupOp::MountMqueue { dest, .. }
            | SetupOp::MountTmpfs { dest, .. }
            | SetupOp::MountDev { dest, .. }
            | SetupOp::MountProc { dest, .. }
            | SetupOp::RoOverlayMount { dest, .. }
            | SetupOp::TmpOverlayMount { dest, .. }
            | SetupOp::OverlayMount { dest, .. }
            | SetupOp::DevBindMount { dest, .. }
            | SetupOp::RoBindMount { dest, .. }
            | SetupOp::BindMount { dest, .. } => Some(dest),
            _ => None,
        }
    }

    pub fn dest_mut(&mut self) -> Option<&mut PathBuf> {
        match self {
            SetupOp::Chmod { dest, .. }
            | SetupOp::RemountRoNoRecursive { dest, .. }
            | SetupOp::MakeSymlink { dest, .. }
            | SetupOp::MakeRoBindFile { dest, .. }
            | SetupOp::MakeBindFile { dest, .. }
            | SetupOp::MakeFile { dest, .. }
            | SetupOp::MakeDir { dest, .. }
            | SetupOp::MountMqueue { dest, .. }
            | SetupOp::MountTmpfs { dest, .. }
            | SetupOp::MountDev { dest, .. }
            | SetupOp::MountProc { dest, .. }
            | SetupOp::RoOverlayMount { dest, .. }
            | SetupOp::TmpOverlayMount { dest, .. }
            | SetupOp::OverlayMount { dest, .. }
            | SetupOp::DevBindMount { dest, .. }
            | SetupOp::RoBindMount { dest, .. }
            | SetupOp::BindMount { dest, .. } => Some(dest),
            _ => None,
        }
    }

    pub fn perms(&self) -> Option<Mode> {
        match self {
            SetupOp::Chmod { perms, .. }
            | SetupOp::RemountRoNoRecursive { perms, .. }
            | SetupOp::MakeSymlink { perms, .. }
            | SetupOp::MakeRoBindFile { perms, .. }
            | SetupOp::MakeBindFile { perms, .. }
            | SetupOp::MakeFile { perms, .. }
            | SetupOp::MakeDir { perms, .. }
            | SetupOp::MountMqueue { perms, .. }
            | SetupOp::MountTmpfs { perms, .. }
            | SetupOp::MountDev { perms, .. }
            | SetupOp::MountProc { perms, .. }
            | SetupOp::RoOverlayMount { perms, .. }
            | SetupOp::TmpOverlayMount { perms, .. }
            | SetupOp::OverlayMount { perms, .. }
            | SetupOp::DevBindMount { perms, .. }
            | SetupOp::RoBindMount { perms, .. }
            | SetupOp::BindMount { perms, .. } => *perms,
            _ => None,
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _LockFile {
    pub path: *const libc::c_char,
    pub fd: libc::c_int,
    pub next: *mut LockFile,
}

pub type LockFile = _LockFile;

#[derive(Copy, Clone)]
#[repr(C)]

pub struct _SeccompProgram {
    pub program: sock_fprog,
    pub next: *mut SeccompProgram,
}

pub type SeccompProgram = _SeccompProgram;

/*
pub static mut argv0: *const libc::c_char = 0 as *const libc::c_char;
pub static mut host_tty_dev: *const libc::c_char = 0 as *const libc::c_char;
pub static mut is_privileged: bool = false;
pub static mut next_overlay_src_count: libc::c_int = 0;
pub static mut next_perms: libc::c_int = -1;
pub static mut next_size_arg: size_t = 0;
pub static mut opt_args_data: *mut libc::c_char = std::ptr::null_mut() as *mut libc::c_char;
pub static mut opt_argv0: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_as_pid_1: bool = false;
pub static mut opt_assert_userns_disabled: bool = false;
pub static mut opt_block_fd: libc::c_int = -1;
pub static mut opt_chdir_path: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_die_with_parent: bool = false;
pub static mut opt_disable_userns: bool = false;
pub static mut opt_exec_label: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_file_label: *const libc::c_char = std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_info_fd: libc::c_int = -1;
pub static mut opt_json_status_fd: libc::c_int = -1;
pub static mut opt_needs_devpts: bool = false;
pub static mut opt_new_session: bool = false;
pub static mut opt_pidns_fd: libc::c_int = -1;
pub static mut opt_sandbox_gid: gid_t = gid_t::MAX;
pub static mut opt_sandbox_hostname: *const libc::c_char =
    std::ptr::null_mut() as *const libc::c_char;
pub static mut opt_sandbox_uid: uid_t = uid_t::MAX;
pub static mut opt_seccomp_fd: libc::c_int = -1;
pub static mut opt_sync_fd: libc::c_int = -1;
pub static mut opt_tmp_overlay_count: libc::c_int = 0;

pub static mut opt_unshare_cgroup: bool = false;
pub static mut opt_unshare_cgroup_try: bool = false;
pub static mut opt_unshare_ipc: bool = false;
pub static mut opt_unshare_net: bool = false;
pub static mut opt_unshare_pid: bool = false;
pub static mut opt_unshare_user: bool = false;
pub static mut opt_unshare_user_try: bool = false;
pub static mut opt_unshare_uts: bool = false;
pub static mut opt_userns2_fd: libc::c_int = -1;
pub static mut opt_userns_block_fd: libc::c_int = -1;
pub static mut opt_userns_fd: libc::c_int = -1;
pub static mut overflow_gid: gid_t = 0;
pub static mut overflow_uid: uid_t = 0;
pub static mut proc_fd: libc::c_int = -1;
pub static mut real_gid: gid_t = 0;
pub static mut real_uid: uid_t = 0;
*/

#[derive(Debug)]
pub struct State {
    pub operations: Vec<SetupOp>,
    pub host_tty_dev: Option<PathBuf>,
    pub is_privileged: bool,
    pub as_pid1: bool,
    pub assert_userns_disable: bool,
    pub chdir_path: Option<PathBuf>,
    pub die_with_parent: bool,
    pub disable_userns: bool,
    pub needs_devpts: bool,
    pub new_session: bool,
    pub sandbox_gid: Option<Gid>,
    pub sandbox_hostname: Option<OsString>,
    pub sandbox_uid: Option<Uid>,
    pub tmp_overlay_coumt: usize,

    pub unshare_cgroup: bool,
    pub unshare_cgroup_try: bool,

    pub unshare_ipc: bool,
    pub unshare_net: bool,
    pub unshare_pid: bool,

    pub unshare_user: bool,
    pub unshare_user_try: bool,

    pub unshare_uts: bool,

    pub overflow_gid: Gid,
    pub overflow_uid: Uid,

    pub proc_fd: Option<OwnedFd>,

    pub real_gid: Gid,
    pub real_uid: Uid,

    pub change_cap: bool,
    pub requested_caps: caps::CapsHashSet,

    pub env: HashMap<OsString, OsString>,

    pub id_cgroup: Option<ino_t>,
    pub id_ipc: Option<ino_t>,
    pub id_net: Option<ino_t>,
    pub id_pid: Option<ino_t>,
    pub id_uts: Option<ino_t>,
}

const NS_INFO: [NsInfo; 6] = [
    NsInfo {
        name: c"cgroup",
        do_unshare: |state: &mut State| Some(&mut state.unshare_cgroup),
        id: |state: &mut State| (&mut state.id_cgroup),
    },
    NsInfo {
        name: c"ipc",
        do_unshare: |state: &mut State| Some(&mut state.unshare_ipc),
        id: |state: &mut State| (&mut state.id_ipc),
    },
    NsInfo {
        name: c"mnt",
        do_unshare: |_: &mut State| None,
        id: |_: &mut State| unreachable!("No id for mnt"),
    },
    NsInfo {
        name: c"net",
        do_unshare: |state: &mut State| Some(&mut state.unshare_net),
        id: |state: &mut State| (&mut state.id_net),
    },
    NsInfo {
        name: c"pid",
        do_unshare: |state: &mut State| Some(&mut state.unshare_pid),
        id: |state: &mut State| (&mut state.id_pid),
    },
    /* user namespace info omitted because it
     * is not (yet) valid when we obtain the
     * namespace info (get un-shared later) */
    NsInfo {
        name: c"uts",
        do_unshare: |state: &mut State| Some(&mut state.unshare_uts),
        id: |state: &mut State| (&mut state.id_uts),
    },
];

#[derive(Debug)]
pub enum StateCreationError {
    NoTTYNameForStdout(Errno),
    OverflowIdReadErr(std::io::Error),
    OverflowIdParseErr(std::num::ParseIntError),
}

impl State {
    fn new() -> Result<Self, StateCreationError> {
        let overflow_uid_data = std::fs::read_to_string("/proc/sys/kernel/overflowuid")
            .map_err(StateCreationError::OverflowIdReadErr)?;
        let overflow_uid = Uid::from_raw(
            overflow_uid_data
                .parse::<u32>()
                .map_err(StateCreationError::OverflowIdParseErr)?,
        );
        let overflow_gid_data = std::fs::read_to_string("/proc/sys/kernel/overflowgid")
            .map_err(StateCreationError::OverflowIdReadErr)?;
        let overflow_gid = Gid::from_raw(
            overflow_gid_data
                .parse::<u32>()
                .map_err(StateCreationError::OverflowIdParseErr)?,
        );
        let host_tty_dev = std::io::stdout()
            .is_terminal()
            .then(|| nix::unistd::ttyname(std::io::stdout()))
            .transpose()
            .map_err(StateCreationError::NoTTYNameForStdout)?;

        Ok(Self {
            operations: Vec::new(),
            is_privileged: false,
            as_pid1: false,
            assert_userns_disable: false,
            chdir_path: None,
            die_with_parent: false,
            disable_userns: false,
            needs_devpts: false,
            new_session: false,
            sandbox_gid: None,
            sandbox_hostname: None,
            sandbox_uid: None,
            tmp_overlay_coumt: 0,
            unshare_cgroup: false,
            unshare_cgroup_try: false,
            unshare_ipc: false,
            unshare_net: false,
            unshare_pid: false,
            unshare_user: false,
            unshare_user_try: false,
            unshare_uts: false,
            overflow_gid,
            overflow_uid,
            host_tty_dev,
            proc_fd: None,
            real_gid: Gid::current(),
            real_uid: Uid::current(),
            change_cap: false,
            requested_caps: Default::default(),
            env: Default::default(),
            id_cgroup: None,
            id_ipc: None,
            id_net: None,
            id_pid: None,
            id_uts: None,
        })
    }
}

static mut lock_files: *mut LockFile = std::ptr::null_mut() as *mut LockFile;

static mut last_lock_file: *mut LockFile = std::ptr::null_mut() as *mut LockFile;

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

#[derive(Clone, Debug, thiserror::Error)]
#[error("prctl error: {0}")]
struct HandleDieWithParentError(#[from] Errno);

fn handle_die_with_parent(state: &State) -> Result<(), HandleDieWithParentError> {
    if state.die_with_parent {
        nix::sys::prctl::set_pdeathsig(Signal::SIGKILL)?;
    }
    Ok(())
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("sigprocmask: {0}")]
struct BlockSigchild(#[from] Errno);

fn block_sigchild() -> Result<(), BlockSigchild> {
    use nix::sys::signal;
    use nix::sys::wait;
    let mut mask = signal::SigSet::empty();
    mask.add(signal::Signal::SIGCHLD);

    signal::sigprocmask(signal::SigmaskHow::SIG_BLOCK, Some(&mask), None)?;

    while wait::waitpid(None, Some(wait::WaitPidFlag::WNOHANG)).is_ok() {}
    Ok(())
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("sigprocmask: {0}")]
struct UnblockSigchild(#[from] Errno);
fn unblock_sigchild() -> Result<(), UnblockSigchild> {
    use nix::sys::signal;
    let mut mask = signal::SigSet::empty();
    mask.add(signal::Signal::SIGCHLD);

    signal::sigprocmask(signal::SigmaskHow::SIG_UNBLOCK, Some(&mask), None)?;
    Ok(())
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

fn close_extra_fds_closure(data: &[RawFd]) -> impl Fn(RawFd) + use<'_> {
    |fd: RawFd| {
        if fd > 2 || !data.contains(&fd) {
            let _ = nix::unistd::close(fd);
        }
    }
}
/*
  if (WIFEXITED(status))
    return WEXITSTATUS(status);

  / * The process died of a signal, we can't really report that, but we
   * can at least be bash-compatible. The bash manpage says:
   *   The return value of a simple command is its
   *   exit status, or 128+n if the command is
   *   terminated by signal n.
   * /
  if (WIFSIGNALED(status))
    return 128 + WTERMSIG(status);

  / * Weird? * /
  return 255;
*/
fn propagate_exit_status(status: libc::c_int) -> libc::c_int {
    if libc::WIFEXITED(status) {
        return libc::WEXITSTATUS(status);
    }
    if libc::WIFSIGNALED(status) {
        return 128 + libc::WTERMSIG(status);
    }
    return 255;
}

unsafe fn dump_info(fd: libc::c_int, output: *const libc::c_char, exit_on_error: bool) {
    let len = strlen(output);
    if write_to_fd(fd, output, len as ssize_t) != 0 && exit_on_error {
        die_with_error!(c"Write to info_fd".as_ptr());
    }
}

fn monitor_child(
    state: &State,
    event_fd: Option<EventFd>,
    child_pid: Pid,
    setup_finished_fd: Option<OwnedFd>,
) -> libc::c_int {
    let mut dont_close: [RawFd; 4] = [0; 4];
    let mut j = 1;
    if let Some(fd) = &event_fd {
        dont_close[j] = fd.as_raw_fd();
        j += 1;
    }
    if let Some(fd) = &setup_finished_fd {
        dont_close[j] = fd.as_raw_fd();
        j += 1;
    }
    assert!(j < dont_close.len());
    fdwalk(
        state.proc_fd.as_ref().map(|f| f.as_fd()).unwrap(),
        close_extra_fds_closure(&dont_close[..j]),
    );
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    let signal_fd = match nix::sys::signalfd::SignalFd::with_flags(
        &mask,
        SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK,
    ) {
        Err(e) => panic!("Can't create signalfd: {e}"),
        Ok(fd) => fd,
    };
    let mut fds = std::mem::MaybeUninit::<[PollFd; 2]>::zeroed();
    let mut fds_len = 1usize;
    {
        let pfd = fds.as_mut_ptr().cast::<PollFd>();
        unsafe { pfd.write(PollFd::new(signal_fd.as_fd(), PollFlags::POLLIN)) };
    }
    if let Some(fd) = &event_fd {
        {
            let pfd = fds.as_mut_ptr().cast::<PollFd>().wrapping_offset(1);
            unsafe { pfd.write(PollFd::new(fd.as_fd(), PollFlags::POLLIN)) };
        }
        fds_len += 1;
    }
    loop {
        let pollfds =
            unsafe { std::slice::from_raw_parts_mut(fds.as_mut_ptr().cast::<PollFd>(), fds_len) };
        pollfds.iter_mut().for_each(|fd| {
            fd.revents();
        });
        let res = nix::poll::poll(pollfds, PollTimeout::NONE);
        if let Err(e) = res {
            if e != Errno::EINTR {
                panic!("poll: {e}");
            }
        }
        if let Some(fd) = &event_fd {
            let mut val = 0u64;
            let val_bytes = unsafe {
                std::slice::from_raw_parts_mut(&raw mut val as *mut u8, size_of_val(&val))
            };
            let s = nix::unistd::read(fd.as_raw_fd(), val_bytes);
            if !matches!(s, Err(Errno::EINTR | Errno::EAGAIN)) {
                panic!("read eventfd: {}", s.unwrap_err());
            } else if s == Ok(8) {
                let exitc = (val - 1) as i32;
                return exitc;
            }
        }
        let s = signal_fd.read_signal();
        if !matches!(s, Err(Errno::EINTR | Errno::EAGAIN)) {
            panic!("read signalfd: {}", s.unwrap_err());
        }
        loop {
            let Ok(died_pid) = nix::sys::wait::waitpid(None, Some(WaitPidFlag::WNOHANG)) else {
                break;
            };

            if died_pid.pid() == Some(child_pid) {
                let exitc = match died_pid {
                    nix::sys::wait::WaitStatus::Exited(_, status) => status,
                    nix::sys::wait::WaitStatus::Signaled(_, status, _) => 128 + status as i32,
                    _ => 255,
                };
                return exitc;
            }
        }
    }
}

fn do_init(state: &State, event_fd: Option<EventFd>, initial_pid: Pid) -> libc::c_int {
    let mut initial_exit_status = 1;
    handle_die_with_parent(state);
    //seccomp_programs_apply();
    loop {
        let child = nix_retry!(nix::sys::wait::wait());
        match child {
            Ok(c) if c.pid() == Some(initial_pid) => {
                initial_exit_status = match c {
                    nix::sys::wait::WaitStatus::Exited(_, status) => status,
                    nix::sys::wait::WaitStatus::Signaled(_, status, _) => 128 + status as i32,
                    _ => 255,
                };
                if let Some(fd) = &event_fd {
                    let val = (initial_exit_status + 1) as u64;
                    let val_bytes = unsafe {
                        std::slice::from_raw_parts(&raw const val as *const u8, size_of_val(&val))
                    };
                    let _ = nix_retry!(nix::unistd::write(fd, &val_bytes));
                }
            }
            Err(e) if e != Errno::ECHILD => {
                panic!("init wait(): {e}")
            }
            Err(_) => break,
            Ok(_) => {}
        };
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

fn set_required_caps() -> Result<(), CapsError> {
    let caps = [
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_SYS_CHROOT,
        Capability::CAP_NET_ADMIN,
        Capability::CAP_SETUID,
        Capability::CAP_SETGID,
        Capability::CAP_SYS_PTRACE,
    ]
    .into_iter()
    .collect();
    caps::set(None, caps::CapSet::Effective, &caps)?;
    caps::set(None, caps::CapSet::Permitted, &caps)?;
    Ok(())
}

fn drop_all_caps(state: &State, keep_requested_caps: bool) -> Result<(), caps::errors::CapsError> {
    let set = if keep_requested_caps {
        if !state.change_cap && state.real_uid.is_root() {
            assert!(!state.is_privileged);
            return Ok(());
        }
        state.requested_caps.clone()
    } else {
        CapsHashSet::new()
    };
    caps::set(None, caps::CapSet::Effective, &set)?;
    caps::set(None, caps::CapSet::Permitted, &set)?;
    caps::set(None, caps::CapSet::Inheritable, &set)?;
    Ok(())
}

unsafe fn has_caps() -> bool {
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
        die_with_error!(c"capget failed".as_ptr());
    }
    return data[0].permitted != 0 || data[1].permitted != 0;
}

fn prctl_caps_rust(
    caps: CapsHashSet,
    do_cap_bounding: bool,
    do_set_ambient: bool,
) -> Result<(), caps::errors::CapsError> {
    for cap in caps::all() {
        let keep = caps.contains(&cap);
        if keep && do_set_ambient {
            if let Ok(()) = caps::runtime::ambient_set_supported() {
                match caps::raise(None, caps::CapSet::Ambient, cap) {
                    Err(e) => match Errno::last() {
                        Errno::EINVAL | Errno::EPERM => Ok(()),
                        _ => Err(e),
                    },
                    Ok(()) => Ok(()),
                }?;
            }
        }
        if !keep && do_cap_bounding {
            match caps::raise(None, caps::CapSet::Bounding, cap) {
                Err(e) => match Errno::last() {
                    Errno::EINVAL | Errno::EPERM => Ok(()),
                    _ => Err(e),
                },
                Ok(()) => Ok(()),
            }?;
        }
    }
    Ok(())
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

fn drop_cap_bounding_set(state: &State, drop_all: bool) {
    if !drop_all {
        prctl_caps_rust(state.requested_caps.clone(), true, false);
    } else {
        prctl_caps_rust(Default::default(), true, false);
    };
}

fn set_ambient_capabilities(state: &State) {
    if state.is_privileged {
        return;
    }
    prctl_caps_rust(state.requested_caps.clone(), false, true);
}

#[derive(Debug, thiserror::Error)]
enum AcquirePrivError {
    #[error("Unknown error: {0}")]
    NixError(#[from] Errno),
    #[error("Cap Error: {0}")]
    CapError(#[from] caps::errors::CapsError),
    #[error("Unexpected setuid user {0}, should be 0")]
    InvalidSetuid(Uid),
    #[error("Unable to set fsuid: {0}")]
    FsUidSetError(Errno),
    #[error("Unable to set fsuid: mismatched fsuid")]
    FsUidSetErrorBis,
    #[error("Unexpected capabilities but not setuid, old file caps config?")]
    UnexpectedCapabilities,
}

fn acquire_privs(state: &mut State) -> Result<(), AcquirePrivError> {
    let euid = nix::unistd::geteuid();
    if state.real_uid != euid {
        if !euid.is_root() {
            return Err(AcquirePrivError::InvalidSetuid(euid));
        }
        state.is_privileged = true;
        if nix::unistd::setfsuid(state.real_uid).as_raw() == u32::MAX {
            return Err(AcquirePrivError::FsUidSetError(Errno::last()));
        }
        // == setfsuid(-1)
        let new_fsuid = nix::unistd::setfsuid(Uid::from_raw(uid_t::MAX));
        if new_fsuid != state.real_uid {
            return Err(AcquirePrivError::FsUidSetErrorBis);
        }
        prctl_caps_rust(CapsHashSet::new(), true, false);
        set_required_caps().map_err(AcquirePrivError::CapError)?;
    } else if !state.real_uid.is_root()
        && !caps::read(None, caps::CapSet::Permitted)
            .map_err(AcquirePrivError::CapError)?
            .is_empty()
    {
        return Err(AcquirePrivError::UnexpectedCapabilities);
    } else if state.real_uid.is_root() {
        let caps = caps::read(None, caps::CapSet::Effective)?;
        state.requested_caps = caps;
    }
    Ok(())
}

fn switch_to_user_with_privs(state: &State) {
    if state.unshare_user {
        drop_cap_bounding_set(state, false);
    }
    if !state.is_privileged {
        return;
    }
    if let Err(e) = nix::sys::prctl::set_keepcaps(true) {
        panic!("prctl(PR_SET_KEEPCAPS) failed: {e}");
    }
    if let Err(e) = nix::unistd::setuid(state.sandbox_uid.unwrap_or(state.real_uid)) {
        panic!("unable to drop root uid: {e}");
    }
    set_required_caps();
}

fn drop_privs(state: &State, keep_requested_caps: bool, already_changed_uid: bool) {
    assert!(!keep_requested_caps || !state.is_privileged);
    if state.is_privileged && !already_changed_uid {
        if let Err(e) = nix::unistd::setuid(state.sandbox_uid.unwrap_or(state.real_uid)) {
            panic!("unable to drop root uid: {e}");
        }
    }
    drop_all_caps(state, keep_requested_caps);
    if let Err(e) = nix::sys::prctl::set_dumpable(true) {
        panic!("can't set dumpable: {e}");
    }
}

fn write_uid_gid_map(
    state: &State,
    sandbox_uid: Uid,
    parent_uid: Uid,
    sandbox_gid: Gid,
    parent_gid: Gid,
    pid: Option<Pid>,
    deny_groups: bool,
    map_root: bool,
) {
    use std::io::Write;
    let dir: Cow<'static, CStr> = if let Some(pid) = pid {
        CString::new(format!("{pid}").into_bytes()).unwrap().into()
    } else {
        c"self".into()
    };
    let dir_fd = match nix::fcntl::openat(
        state.proc_fd.as_ref().map(|fd| fd.as_raw_fd()),
        &*dir,
        OFlag::O_PATH,
        Mode::empty(),
    ) {
        Err(e) => panic!("open /proc/{} failed: {e}", dir.to_string_lossy()),
        Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
    };
    let mut uid_map = Vec::with_capacity(128);
    if map_root && !parent_uid.is_root() && !sandbox_uid.is_root() {
        writeln!(
            &mut uid_map,
            "0 {} 1\n{} {} 1",
            state.overflow_uid, sandbox_uid, parent_uid,
        )
        .unwrap();
    } else {
        writeln!(&mut uid_map, "{} {} 1", sandbox_uid, parent_uid,).unwrap();
    }
    let mut gid_map = Vec::with_capacity(128);
    if map_root && parent_gid.as_raw() != 0 && sandbox_gid.as_raw() != 0 {
        writeln!(
            &mut gid_map,
            "0 {} 1\n{} {} 1",
            state.overflow_gid, sandbox_gid, parent_gid,
        )
        .unwrap();
    } else {
        writeln!(&mut gid_map, "{} {} 1", sandbox_gid, parent_gid,).unwrap();
    }
    let old_fsuid = if state.is_privileged {
        Some(nix::unistd::setfsuid(Uid::from_raw(0)))
    } else {
        None
    };
    if let Err(e) = write_file_at_rust(Some(dir_fd.as_fd()), c"uid_map", &uid_map) {
        panic!("setting up uid map: {e}");
    }
    if deny_groups {
        if let Err(e) = write_file_at_rust(Some(dir_fd.as_fd()), c"setgroups", b"deny\n") {
            if e != Errno::ENOENT {
                panic!("error writing to setgroups: {e}");
            }
        }
    }
    if let Err(e) = write_file_at_rust(Some(dir_fd.as_fd()), c"gid_map", &gid_map) {
        panic!("setting up gid map: {e}");
    }
    if state.is_privileged {
        nix::unistd::setfsuid(old_fsuid.unwrap());
        if nix::unistd::setfsuid(Uid::from_raw(u32::MAX)) != state.real_uid {
            panic!("Unable to re-set fsuid");
        }
    }
}

fn resolve_symlinks_in_ops(op_list: &mut [SetupOp]) {
    for op in op_list {
        match op {
            SetupOp::RoBindMount {
                allow_not_exist,
                src,
                ..
            }
            | SetupOp::DevBindMount {
                allow_not_exist,
                src,
                ..
            }
            | SetupOp::BindMount {
                allow_not_exist,
                src,
                ..
            }
            | SetupOp::OverlaySrc {
                allow_not_exist,
                src,
                ..
            }
            | SetupOp::OverlayMount {
                allow_not_exist,
                src,
                ..
            } => {
                let old_src = std::mem::take(src);
                let real_path_raw = match old_src.with_nix_path(|p| {
                    match unsafe { libc::realpath(p.as_ptr(), ptr::null_mut()) } {
                        p if p.is_null() => Err(Errno::last()),
                        p => Ok(p),
                    }
                }) {
                    Err(e) | Ok(Err(e)) => Err(e),
                    Ok(Ok(p)) => Ok(p),
                };
                match real_path_raw {
                    Err(Errno::ENOENT) if *allow_not_exist => *src = old_src,
                    Err(e) => panic!("Can't find source path for {}: {e}", old_src.display()),
                    Ok(p) => {
                        // safety: the ptr is not null (would be an Err(e)), and is a valid Cstr,
                        // since it is the garenty of realpath if the last argument is NULL (the
                        // will be malloc'ed, meaning that we need to free it)
                        let cstr = unsafe { CStr::from_ptr(p) };
                        *src = PathBuf::from(OsStr::from_bytes(cstr.to_bytes()));
                        unsafe { libc::free(p.cast()) };
                    }
                }
            }
            _ => {}
        }
    }
}

fn print_version_and_exit() -> ! {
    unsafe { libc::printf(c"%s\n".as_ptr(), PACKAGE_STRING.as_ptr()) };
    std::process::exit(0);
}

pub fn main_0(argc: libc::c_int, argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut state = State::new().expect("TODO:");
    state.env = std::env::vars_os().collect();

    acquire_privs(&mut state);
    nix::sys::prctl::set_no_new_privs().expect("TODO:");
    // parse_args(
    // &mut argc,
    // &mut argv as *mut *mut *mut libc::c_char as *mut *mut *const libc::c_char,
    // );
    if !state.requested_caps.is_empty() && state.is_privileged {
        panic!("--cap-add in setuid mode can be used only by root");
    }
    if state.disable_userns && !state.unshare_user {
        panic!("--disable-userns requires --unshare-user");
    }
    if !state.unshare_user_try && nix::sys::stat::stat(c"/proc/self/ns/user").is_ok() {
        let mut disabled = false;
        if nix::sys::stat::stat(c"/sys/module/user_namespace/parameters/enable").is_ok() {
            let enable = std::fs::read("/sys/module/user_namespace/parameters/enable");
            match enable {
                Ok(n) if n.get(0) == Some(&b'N') => disabled = true,
                _ => {}
            }
        }
        if nix::sys::stat::stat(c"/proc/sys/user/max_user_namespaces").is_ok() {
            let max_user_ns = std::fs::read("/sys/module/user_namespace/parameters/enable");
            match max_user_ns {
                Ok(n) if n == b"0\n" => disabled = true,
                _ => {}
            }
        }
        if !disabled {
            state.unshare_user = true;
        }
    }
    if state.sandbox_uid.is_none() {
        state.sandbox_uid = Some(state.real_uid);
    }
    if state.sandbox_gid.is_none() {
        state.sandbox_gid = Some(state.real_gid);
    }
    if !state.unshare_user && state.sandbox_uid != Some(state.real_uid) {
        panic!("Specifying --uid requires --unshare-user or --userns");
    }
    if !state.unshare_user && state.sandbox_gid != Some(state.real_gid) {
        panic!("Specifying --gid requires --unshare-user or --userns");
    }
    if !state.unshare_uts && state.sandbox_hostname.is_some() {
        panic!("Specifying --hostname requires --unshare-uts");
    }
    if state.as_pid1 && !state.unshare_pid {
        panic!("Specifying --as-pid-1 requires --unshare-pid");
    }
    let proc_fd = nix_retry!(nix::fcntl::openat(
        None,
        c"/proc",
        OFlag::O_PATH,
        Mode::empty()
    ));
    if let Err(e) = proc_fd {
        panic!("Can't open /proc: {e}");
    }
    state.proc_fd = Some(unsafe { OwnedFd::from_raw_fd(proc_fd.unwrap()) });
    let base_path = c"/tmp";
    let event_fd = if state.unshare_pid && !state.as_pid1 {
        match nix::sys::eventfd::EventFd::from_value_and_flags(
            0,
            nix::sys::eventfd::EfdFlags::EFD_CLOEXEC | nix::sys::eventfd::EfdFlags::EFD_NONBLOCK,
        ) {
            Ok(fd) => Some(fd),
            Err(e) => panic!("eventfd(): {e}"),
        }
    } else {
        None
    };
    block_sigchild();
    let mut clone_flags: CloneFlags =
        CloneFlags::from_bits_retain(Signal::SIGCHLD as _) | CloneFlags::CLONE_NEWNS;
    if state.unshare_user {
        clone_flags |= CloneFlags::CLONE_NEWUSER;
    }
    if state.unshare_pid {
        clone_flags |= CloneFlags::CLONE_NEWPID;
    }
    if state.unshare_net {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }
    if state.unshare_ipc {
        clone_flags |= CloneFlags::CLONE_NEWIPC;
    }
    if state.unshare_uts {
        clone_flags |= CloneFlags::CLONE_NEWUTS;
    }
    if state.unshare_cgroup {
        if let Err(e) = nix::sys::stat::stat(c"/proc/self/ns/cgroup") {
            if e == Errno::ENOENT {
                panic!("Cannot create new cgroup namespace because the kernel does not support it");
            } else {
                panic!("stat on /proc/self/ns/cgroup failed: {e}");
            }
        }
        clone_flags |= CloneFlags::CLONE_NEWCGROUP;
    }
    if state.unshare_cgroup_try {
        state.unshare_cgroup = nix::sys::stat::stat(c"/proc/self/ns/cgroup").is_ok();
        if state.unshare_cgroup {
            clone_flags |= CloneFlags::CLONE_NEWCGROUP;
        }
    }
    let child_wait_fd = match nix::sys::eventfd::EventFd::from_value_and_flags(
        0,
        nix::sys::eventfd::EfdFlags::EFD_CLOEXEC,
    ) {
        Err(e) => panic!("eventfd(): {e}"),
        Ok(fd) => fd,
    };
    let pid = match raw_clone(clone_flags) {
        Err(e) => {
            if state.unshare_user {
                if e == Errno::EINVAL {
                    panic!(
                     "Creating new namespace failed, likely because the kernel does not support user namespaces.  bwrap must be installed setuid on such systems."
                )
                } else if e == Errno::EPERM && !state.is_privileged {
                    panic!(
                     "No permissions to creating new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'."                )
                }
            }
            if e == Errno::ENOSPC {
                panic!(
                 "Creating new namespace failed: nesting depth or /proc/sys/user/max_*_namespaces exceeded (ENOSPC)"            )
            }
            panic!("Creating new namespace failed: {e}")
        }
        Ok(pid) => pid,
    };
    let mut ns_uid = state.sandbox_uid.unwrap();
    let mut ns_gid = state.sandbox_gid.unwrap();
    if pid.as_raw() != 0 {
        if state.is_privileged && state.unshare_user {
            write_uid_gid_map(
                &state,
                ns_uid,
                state.real_uid,
                ns_gid,
                state.real_gid,
                Some(pid),
                true,
                state.needs_devpts,
            );
        }
        drop_privs(&state, false, false);
        handle_die_with_parent(&state);
        let mut val = 1;
        let val_bytes =
            unsafe { std::slice::from_raw_parts_mut(&raw mut val as *mut u8, size_of_val(&val)) };

        let _ = nix_retry!(nix::unistd::write(child_wait_fd.as_fd(), val_bytes));
        drop(child_wait_fd);
        return monitor_child(&state, event_fd, pid, None);
    }
    let mut val = 1;
    let val_bytes =
        unsafe { std::slice::from_raw_parts_mut(&raw mut val as *mut u8, size_of_val(&val)) };
    let _ = nix::unistd::read(child_wait_fd.as_raw_fd(), val_bytes);
    drop(child_wait_fd);
    switch_to_user_with_privs(&state);
    if state.unshare_net {
        loopback_setup().unwrap();
    }
    ns_uid = state.sandbox_uid.unwrap();
    ns_gid = state.sandbox_gid.unwrap();
    if !state.is_privileged && state.unshare_user {
        if state.needs_devpts {
            ns_uid = 0.into();
            ns_gid = 0.into();
        }
        write_uid_gid_map(
            &state,
            ns_uid,
            state.real_uid,
            ns_gid,
            state.real_gid,
            None,
            true,
            false,
        );
    }
    let old_umask = nix::sys::stat::umask(Mode::empty());
    resolve_symlinks_in_ops(&mut state.operations);
    if let Err(e) = nix::mount::mount(
        Option::<&CStr>::None,
        c"/",
        Option::<&CStr>::None,
        MsFlags::MS_SILENT | MsFlags::MS_SLAVE | MsFlags::MS_REC,
        Option::<&CStr>::None,
    ) {
        panic!("Failed to make / slave: {e}");
    }
    if let Err(e) = nix::mount::mount(
        Some(c"tmpfs"),
        base_path,
        Some(c"tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        Option::<&CStr>::None,
    ) {
        panic!("Failed to mount tmpfs: {e}");
    }
    let old_cwd = std::env::current_dir().expect("TODO: ");
    if let Err(e) = nix::unistd::chdir(base_path) {
        panic!("chdir base_path: {e}");
    }
    if let Err(e) = nix::unistd::mkdir(c"newroot", Mode::from_bits_truncate(0o755)) {
        panic!("Creating newroot failed: {e}");
    }
    if let Err(e) = nix::mount::mount(
        Some(c"newroot"),
        c"newroot",
        Option::<&CStr>::None,
        MsFlags::MS_SILENT | MsFlags::MS_MGC_VAL | MsFlags::MS_BIND | MsFlags::MS_REC,
        Option::<&CStr>::None,
    ) {
        panic!("setting up newroot bind: {e}");
    }
    if let Err(e) = nix::unistd::mkdir(c"oldroot", Mode::from_bits_truncate(0o755)) {
        panic!("Creating oldroot failed: {e}");
    }
    for i in 0..state.tmp_overlay_coumt {
        let dirname = format!("tmp-overlay-upper-{i}");
        if let Err(e) = nix::unistd::mkdir(dirname.as_str(), Mode::from_bits_truncate(0o755)) {
            panic!("Creating --tmp-overlay upperdir failed: {e}");
        }
        let dirname = format!("tmp-overlay-work-{i}");
        if let Err(e) = nix::unistd::mkdir(dirname.as_str(), Mode::from_bits_truncate(0o755)) {
            panic!("Creating --tmp-overlay workdir failed: {e}");
        }
    }
    if let Err(e) = pivot_root(base_path, c"oldroot") {
        panic!("pivot_root: {e}");
    }
    if let Err(e) = nix::unistd::chdir(c"/") {
        panic!("chdir / (base path): {e}");
    }
    if state.is_privileged {
        let privsep_sockets = match nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::SeqPacket,
            nix::sys::socket::SockProtocol::NetlinkRoute,
            SockFlag::SOCK_CLOEXEC,
        ) {
            Err(e) => panic!("Can't create privsep socket: {e}"),
            Ok(fd) => fd,
        };
        let child = match unsafe { nix::unistd::fork() } {
            Err(e) => panic!("Can't fork unprivileged helper: {e}"),
            Ok(r) => r,
        };
        if let ForkResult::Child = child {
            drop_privs(&state, false, true);
            nix::unistd::close(privsep_sockets.0.as_raw_fd());
            setup_newroot(&mut state, Some(privsep_sockets.1.as_raw_fd()));
            std::process::exit(0);
        } else if let ForkResult::Parent { child } = child {
            fn handle_priv_op<'s, 'fd, 'buf>(
                state: &'s State,
                fd: BorrowedFd<'fd>,
                buffer: &'buf mut [u8],
            ) -> Result<(bool, &'buf mut [u8]), ()> {
                let bytes = nix_retry!(nix::unistd::read(fd.as_raw_fd(), &mut buffer[..]))
                    .map_err(|_| ())?;
                let msg: PrivilegedOp = postcard::from_bytes(&buffer[..bytes]).map_err(|_| ())?;

                let end = matches!(msg, PrivilegedOp::Done);
                let ret = privileged_op(state, None, msg);
                buffer.fill(0);

                postcard::to_slice(&ret, &mut buffer[..])
                    .map_err(|_| ())
                    .map(|b| (end, b))
            }

            let unpriv_socket = privsep_sockets.0;
            let mut buffer = vec![0; 8096];
            let _ = nix::unistd::close(privsep_sockets.1.as_raw_fd());
            loop {
                let (end, buf) =
                    match handle_priv_op(&state, unpriv_socket.as_fd(), &mut buffer[..]) {
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

            let _ = nix_retry!(nix::sys::wait::waitpid(Some(child), None));
        }
    } else {
        setup_newroot(&mut state, None);
    }
    if let Err(e) = nix::mount::mount(
        Some(c"oldroot"),
        c"oldroot",
        Option::<&CStr>::None,
        MsFlags::MS_SILENT | MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        Option::<&CStr>::None,
    ) {
        panic!("Failed to make old root rprivate: {e}");
    }
    if let Err(e) = nix::mount::umount2(c"oldroot", MntFlags::MNT_DETACH) {
        panic!("unmount old root: {e}");
    }
    let oldrootfd = match nix_retry!(nix::fcntl::open(c"/", OFlag::O_PATH, Mode::empty())) {
        Err(e) => panic!("can't open /: {e}"),
        Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
    };
    if let Err(e) = nix::unistd::chdir(c"/newroot") {
        panic!("chdir /newroot: {e}");
    }
    if let Err(e) = pivot_root(c".", c".") {
        panic!("pivot_root(/newroot): {e}");
    }
    if let Err(e) = nix::unistd::fchdir(oldrootfd.as_raw_fd()) {
        panic!("fchdir to oldroot: {e}");
    }
    if let Err(e) = nix::mount::umount2(c".", MntFlags::MNT_DETACH) {
        panic!("umount old root: {e}");
    }
    if let Err(e) = nix::unistd::chdir(c"/") {
        panic!("chdir /: {e}");
    }
    if state.unshare_user
        && (Some(ns_uid) != state.sandbox_uid
            || Some(ns_gid) != state.sandbox_gid
            || state.disable_userns)
    {
        if state.disable_userns {
            let sysctl_fd = match nix_retry!(nix::fcntl::openat(
                state.proc_fd.as_ref().map(|f| f.as_raw_fd()),
                c"sys/user/max_user_namespaces",
                OFlag::O_WRONLY,
                Mode::empty()
            )) {
                Err(e) => panic!("cannot open /proc/sys/user/max_user_namespaces: {e}"),
                Ok(fd) => unsafe { OwnedFd::from_raw_fd(fd) },
            };
            if let Err(e) = write_to_fd_rust(sysctl_fd.as_fd(), b"1") {
                panic!("sysctl user.max_user_namespaces = 1: {e}");
            }
        }
        if let Err(e) = nix::sched::unshare(CloneFlags::CLONE_NEWUSER) {
            panic!("unshare user ns: {e}");
        }
        drop_cap_bounding_set(&state, false);
        write_uid_gid_map(
            &state,
            state.sandbox_uid.unwrap(),
            ns_uid,
            state.sandbox_gid.unwrap(),
            ns_gid,
            None,
            false,
            false,
        );
    }
    if state.disable_userns || state.assert_userns_disable {
        if let Err(e) = nix::sched::unshare(CloneFlags::CLONE_NEWUSER) {
            panic!("creation of new user namespaces was not disabled as requested: {e}");
        }
    }
    drop_privs(&state, !state.is_privileged, true);
    nix::sys::stat::umask(old_umask);
    let mut new_cwd = PathBuf::from("/");
    if let Some(ref chdir) = state.chdir_path {
        if let Err(e) = nix::unistd::chdir(chdir) {
            panic!("Can't chdir to {}: {e}", chdir.display());
        }
        new_cwd = chdir.to_path_buf();
    } else if nix::unistd::chdir(&old_cwd).is_ok() {
        new_cwd = old_cwd;
    } else {
        let home = std::env::var_os("HOME");
        if let Some(Ok(())) = home.as_ref().map(|p| nix::unistd::chdir(p.as_os_str())) {
            new_cwd = home.unwrap().into();
        }
    }
    std::env::set_var("PWD", new_cwd);
    if state.new_session {
        if let Err(e) = nix::unistd::setsid() {
            panic!("setsid: {e}");
        }
    }
    if !state.as_pid1 && state.unshare_pid {
        let fork_result = match unsafe { nix::unistd::fork() } {
            Err(e) => panic!("Can't fork for pid 1: {e}"),
            Ok(pid) => pid,
        };
        if let ForkResult::Parent { child } = fork_result {
            drop_all_caps(&state, false);
            let mut dont_close: [RawFd; 3] = [0; 3];
            let mut j = 0;
            if let Some(fd) = &event_fd {
                dont_close[j] = fd.as_raw_fd();
                j += 1;
            }
            fdwalk(
                state.proc_fd.as_ref().map(|f| f.as_fd()).unwrap(),
                close_extra_fds_closure(&dont_close[..j]),
            );
            return do_init(&state, event_fd, child);
        }
    }
    // we close proc_fd
    let _ = state.proc_fd.take();

    unblock_sigchild();
    handle_die_with_parent(&state);
    if !state.is_privileged {
        set_ambient_capabilities(&state);
    }

    todo!()
    /*
    let exec_path = *argv.offset(0);
    // TODO: change to execvep, and create manual array of envvar
    if execvp(exec_path, argv as *const *const libc::c_char) == -1 {
        die_with_error!(c"execvp %s".as_ptr(), exec_path,);
    }
    return 0;
    */
}
