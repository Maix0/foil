pub use crate::errno;
use ::libc;

#[macro_export]
macro_rules! retry {
    ($e:expr) => {
        loop {
            let __result = $e;
            if !(__result == -1 && unsafe { errno!() == ::libc::EINTR }) {
                break __result;
            }
        }
    };
}

pub const __IFA_MAX: libc::c_uint = 12;
pub const __NR_clone: libc::c_int = 56;
pub const __NR_pivot_root: libc::c_int = 155;

pub use libc::access;
pub use libc::bind;
pub use libc::calloc;
pub use libc::chdir;
pub use libc::chmod;
pub use libc::clearenv;
pub use libc::close;
pub use libc::closedir;
pub use libc::cmsghdr;
pub use libc::creat;
pub use libc::dirfd;
pub use libc::eventfd;
pub use libc::execvp;
pub use libc::exit;
pub use libc::fchdir;
pub use libc::fchmod;
pub use libc::fdopendir;
pub use libc::flock;
pub use libc::fork;
pub use libc::fputs;
pub use libc::free;
pub use libc::fstat;
pub use libc::fstatat;
pub use libc::getegid;
pub use libc::getenv;
pub use libc::geteuid;
pub use libc::getgid;
pub use libc::getpid;
pub use libc::getuid;
pub use libc::gid_t;
pub use libc::htonl;
pub use libc::if_nametoindex;
pub use libc::ifaddrs;
pub use libc::in6_addr;
pub use libc::in_addr;
pub use libc::in_addr_t;
pub use libc::in_port_t;
pub use libc::ino_t;
pub use libc::iovec;
pub use libc::isatty;
pub use libc::lstat;
pub use libc::malloc;
pub use libc::memchr;
pub use libc::memcpy;
pub use libc::memset;
pub use libc::mkdir;
pub use libc::mkstemp;
pub use libc::mode_t;
pub use libc::mount;
pub use libc::msghdr;
pub use libc::nfds_t;
pub use libc::nlmsghdr;
pub use libc::open;
pub use libc::openat;
pub use libc::pid_t;
pub use libc::pipe2;
pub use libc::poll;
pub use libc::pollfd;
pub use libc::prctl;
pub use libc::read;
pub use libc::readdir;
pub use libc::readlink;
pub use libc::realloc;
pub use libc::realpath;
pub use libc::recv;
pub use libc::recvmsg;
pub use libc::sa_family_t;
pub use libc::sendmsg;
pub use libc::sendto;
pub use libc::setenv;
pub use libc::setfsuid;
pub use libc::setgid;
pub use libc::sethostname;
pub use libc::setns;
pub use libc::setsid;
pub use libc::setsockopt;
pub use libc::setuid;
pub use libc::sigaddset;
pub use libc::sigemptyset;
pub use libc::signalfd;
pub use libc::signalfd_siginfo;
pub use libc::sigprocmask;
pub use libc::sigset_t;
pub use libc::size_t;
pub use libc::sock_filter;
pub use libc::sock_fprog;
pub use libc::sockaddr;
pub use libc::sockaddr_in;
pub use libc::sockaddr_in6;
pub use libc::sockaddr_nl;
pub use libc::sockaddr_un;
pub use libc::socket;
pub use libc::socketpair;
pub use libc::socklen_t;
pub use libc::sscanf;
pub use libc::ssize_t;
pub use libc::stat;
pub use libc::strcasecmp;
pub use libc::strcat;
pub use libc::strcmp;
pub use libc::strcpy;
pub use libc::strdup;
pub use libc::strerror;
pub use libc::strlen;
pub use libc::strncmp;
pub use libc::strncpy;
pub use libc::strtol;
pub use libc::strtoul;
pub use libc::strtoull;
pub use libc::symlink;
pub use libc::syscall;
pub use libc::sysconf;
pub use libc::timespec;
pub use libc::ttyname;
pub use libc::ucred;
pub use libc::uid_t;
pub use libc::umask;
pub use libc::umount2;
pub use libc::unlink;
pub use libc::unsetenv;
pub use libc::unshare;
pub use libc::wait;
pub use libc::waitpid;
pub use libc::write;
pub use libc::AF_UNIX;
pub use libc::CLONE_NEWCGROUP;
pub use libc::CLONE_NEWIPC;
pub use libc::CLONE_NEWNET;
pub use libc::CLONE_NEWNS;
pub use libc::CLONE_NEWPID;
pub use libc::CLONE_NEWUSER;
pub use libc::CLONE_NEWUTS;
pub use libc::CMSG_DATA;
pub use libc::DIR;
pub use libc::ECHILD;
pub use libc::EFD_CLOEXEC;
pub use libc::EFD_NONBLOCK;
pub use libc::EFD_SEMAPHORE;
pub use libc::ELOOP;
pub use libc::ENOENT;
pub use libc::EPERM;
pub use libc::EROFS;
pub use libc::EXIT_FAILURE;
pub use libc::EXIT_SUCCESS;
pub use libc::FILE;
pub use libc::F_RDLCK;
pub use libc::INADDR_LOOPBACK;
pub use libc::LOG_ERR;
pub use libc::LOG_WARNING;
pub use libc::MS_ACTIVE;
pub use libc::MS_BIND;
pub use libc::MS_DIRSYNC;
pub use libc::MS_I_VERSION;
pub use libc::MS_KERNMOUNT;
pub use libc::MS_LAZYTIME;
pub use libc::MS_MANDLOCK;
pub use libc::MS_MOVE;
pub use libc::MS_NOATIME;
pub use libc::MS_NODEV;
pub use libc::MS_NODIRATIME;
pub use libc::MS_NOEXEC;
pub use libc::MS_NOSUID;
pub use libc::MS_NOUSER;
pub use libc::MS_POSIXACL;
pub use libc::MS_PRIVATE;
pub use libc::MS_RDONLY;
pub use libc::MS_REC;
pub use libc::MS_RELATIME;
pub use libc::MS_REMOUNT;
pub use libc::MS_SHARED;
pub use libc::MS_SILENT;
pub use libc::MS_SLAVE;
pub use libc::MS_STRICTATIME;
pub use libc::MS_SYNCHRONOUS;
pub use libc::MS_UNBINDABLE;
pub use libc::O_CLOEXEC;
pub use libc::O_PATH;
pub use libc::PF_LOCAL;
pub use libc::PF_UNIX;
pub use libc::POLLIN;
pub use libc::PR_CAPBSET_DROP;
pub use libc::PR_CAP_AMBIENT;
pub use libc::PR_CAP_AMBIENT_RAISE;
pub use libc::PR_SET_CHILD_SUBREAPER;
pub use libc::PR_SET_DUMPABLE;
pub use libc::PR_SET_KEEPCAPS;
pub use libc::PR_SET_NO_NEW_PRIVS;
pub use libc::PR_SET_PDEATHSIG;
pub use libc::PR_SET_SECCOMP;
pub use libc::RT_SCOPE_HOST;
pub use libc::RT_SCOPE_LINK;
pub use libc::RT_SCOPE_NOWHERE;
pub use libc::RT_SCOPE_SITE;
pub use libc::RT_SCOPE_UNIVERSE;
pub use libc::SCM_CREDENTIALS;
pub use libc::SCM_RIGHTS;
pub use libc::SECCOMP_MODE_FILTER;
pub use libc::SFD_CLOEXEC;
pub use libc::SFD_NONBLOCK;
pub use libc::SIGCHLD;
pub use libc::SIGKILL;
pub use libc::SIG_BLOCK;
pub use libc::SIG_UNBLOCK;
pub use libc::SOCK_CLOEXEC;
pub use libc::SOCK_DCCP;
pub use libc::SOCK_DGRAM;
pub use libc::SOCK_NONBLOCK;
pub use libc::SOCK_PACKET;
pub use libc::SOCK_RAW;
pub use libc::SOCK_RDM;
pub use libc::SOCK_SEQPACKET;
pub use libc::SOCK_STREAM;
pub use libc::S_IFMT;
pub use libc::WNOHANG;
pub use libc::W_OK;
pub use std::mem::MaybeUninit;

extern "C" {
    pub fn __cmsg_nxthdr(__mhdr: *mut msghdr, __cmsg: *mut cmsghdr) -> *mut cmsghdr;
    pub fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    pub fn cap_from_name(_: *const libc::c_char, _: *mut cap_value_t) -> libc::c_int;
    pub fn capget(header: cap_user_header_t, data: cap_user_data_t) -> libc::c_int;
    pub fn capset(header: cap_user_header_t, data: cap_user_data_t) -> libc::c_int;
    pub fn strappendf(dest: *mut StringBuilder, fmt: *const libc::c_char, args: ...);
    pub fn xasprintf(format: *const libc::c_char, args: ...) -> *mut libc::c_char;
    pub fn get_current_dir_name() -> *mut libc::c_char;
    pub static mut stderr: *mut FILE;
    pub static mut stdout: *mut FILE;
}

pub use crate::bind_mount::*;
pub use crate::bubblewrap::*;
pub use crate::network::*;
pub use crate::utils::*;

pub type cap_value_t = libc::c_int;
pub type cap_user_data_t = *mut __user_cap_data_struct;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct StringBuilder {
    pub buf: *mut libc::c_char,
    pub size: size_t,
    pub offset: size_t,
}

#[inline]
pub unsafe fn steal_pointer(pp: *mut libc::c_void) -> *mut libc::c_void {
    let ptr = pp as *mut *mut libc::c_void;
    let mut ref_0 = 0 as *mut libc::c_void;
    ref_0 = *ptr;
    *ptr = std::ptr::null_mut();
    return ref_0;
}

pub static mut bwrap_level_prefix: bool = true;

#[macro_export]
macro_rules! bwrap_logv {
    ($($t:tt)*) => {};
}
#[macro_export]
macro_rules! bwrap_log {
    ($($t:tt)*) => {};
}

#[macro_export]
macro_rules! die_with_error {
    ($($e:expr),* $(,)?) => {
        let v = ($($e, )*);
        panic!("with_error: {:?}", unsafe{ std::ffi::CStr::from_ptr(v.0)});
    };
}

#[macro_export]
macro_rules! die_with_bind_result {
    ($($e:expr),* $(,)?) => {
        let v = ($($e, )*);
        panic!("bind result: {:?}", v);
    };
}

#[macro_export]
macro_rules! die_with_mount_error {
    ($($e:expr),* $(,)?) => {
        let v = ($($e, )*);
        panic!("with_error: {:?}", unsafe {std::ffi::CStr::from_ptr(v.0)});
    };
}

pub use libc::fprintf;

#[macro_export]
macro_rules! die {
    ($($e:expr),* $(,)?) => {
        let v = ($($e, )*);
        panic!("log: {:?}", unsafe {std::ffi::CStr::from_ptr(v.0)});
    };
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct __user_cap_header_struct {
    pub version: u32,
    pub pid: libc::c_int,
}

pub type cap_user_header_t = *mut __user_cap_header_struct;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __user_cap_data_struct {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

pub const _LINUX_CAPABILITY_VERSION_3: libc::c_int = 0x20080522;
pub const CAP_CHECKPOINT_RESTORE: libc::c_int = 40;
pub const CAP_LAST_CAP: libc::c_int = 40;

pub const PACKAGE_STRING: [libc::c_char; 18] =
    unsafe { *::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"bubblewrap 0.11.0\0") };
