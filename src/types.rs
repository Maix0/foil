pub use crate::errno;
use ::libc;

pub const BIND_DEVICES: bind_option_t = 4;
pub const BIND_MOUNT_ERROR_FIND_DEST_MOUNT: bind_mount_result = 5;
pub const BIND_MOUNT_ERROR_MOUNT: bind_mount_result = 1;
pub const BIND_MOUNT_ERROR_READLINK_DEST_PROC_FD: bind_mount_result = 4;
pub const BIND_MOUNT_ERROR_REALPATH_DEST: bind_mount_result = 2;
pub const BIND_MOUNT_ERROR_REMOUNT_DEST: bind_mount_result = 6;
pub const BIND_MOUNT_ERROR_REMOUNT_SUBMOUNT: bind_mount_result = 7;
pub const BIND_MOUNT_ERROR_REOPEN_DEST: bind_mount_result = 3;
pub const BIND_MOUNT_SUCCESS: bind_mount_result = 0;
pub const BIND_READONLY: bind_option_t = 1;
pub const BIND_RECURSIVE: bind_option_t = 8;
pub const EACCES: libc::c_int = 13 as libc::c_int;
pub const EEXIST: libc::c_int = 17 as libc::c_int;
pub const EFBIG: libc::c_int = 27 as libc::c_int;
pub const EINTR: libc::c_int = 4 as libc::c_int;
pub const EINVAL: libc::c_int = 22 as libc::c_int;
pub const ENOSPC: libc::c_int = 28;
pub const ENOTDIR: libc::c_int = 20 as libc::c_int;
pub const IFA_ADDRESS: libc::c_uint = 1;
pub const IFA_ANYCAST: libc::c_uint = 5;
pub const IFA_BROADCAST: libc::c_uint = 4;
pub const IFA_CACHEINFO: libc::c_uint = 6;
pub const IFA_FLAGS: libc::c_uint = 8;
pub const IFA_F_PERMANENT: libc::c_int = 0x80;
pub const IFA_LABEL: libc::c_uint = 3;
pub const IFA_LOCAL: libc::c_uint = 2;
pub const IFA_MULTICAST: libc::c_uint = 7;
pub const IFA_PROTO: libc::c_uint = 11;
pub const IFA_RT_PRIORITY: libc::c_uint = 9;
pub const IFA_TARGET_NETNSID: libc::c_uint = 10;
pub const IFA_UNSPEC: libc::c_uint = 0;
pub const IFF_ALLMULTI: libc::c_uint = 512;
pub const IFF_AUTOMEDIA: libc::c_uint = 16384;
pub const IFF_BROADCAST: libc::c_uint = 2;
pub const IFF_DEBUG: libc::c_uint = 4;
pub const IFF_DYNAMIC: libc::c_uint = 32768;
pub const IFF_LOOPBACK: libc::c_uint = 8;
pub const IFF_MASTER: libc::c_uint = 1024;
pub const IFF_MULTICAST: libc::c_uint = 4096;
pub const IFF_NOARP: libc::c_uint = 128;
pub const IFF_NOTRAILERS: libc::c_uint = 32;
pub const IFF_POINTOPOINT: libc::c_uint = 16;
pub const IFF_PORTSEL: libc::c_uint = 8192;
pub const IFF_PROMISC: libc::c_uint = 256;
pub const IFF_RUNNING: libc::c_uint = 64;
pub const IFF_SLAVE: libc::c_uint = 2048;
pub const IFF_UP: libc::c_uint = 1;
pub const LONG_MAX: libc::c_long = libc::c_long::MAX;
pub const MS_NOSYMFOLLOW: libc::c_int = 256;
pub const NETLINK_ROUTE: libc::c_int = 0 as libc::c_int;
pub const NLMSG_ALIGNTO: libc::c_uint = 4 as libc::c_uint;
pub const NLMSG_DONE: libc::c_int = 0x3;
pub const NLMSG_ERROR: libc::c_int = 0x2;
pub const NLM_F_ACK: libc::c_int = 0x4 as libc::c_int;
pub const NLM_F_CREATE: libc::c_int = 0x400 as libc::c_int;
pub const NLM_F_EXCL: libc::c_int = 0x200 as libc::c_int;
pub const NLM_F_REQUEST: libc::c_int = 0x1 as libc::c_int;
pub const RTA_ALIGNTO: libc::c_uint = 4 as libc::c_uint;
pub const RTM_BASE: libc::c_uint = 16;
pub const RTM_DELACTION: libc::c_uint = 49;
pub const RTM_DELADDR: libc::c_uint = 21;
pub const RTM_DELADDRLABEL: libc::c_uint = 73;
pub const RTM_DELCHAIN: libc::c_uint = 101;
pub const RTM_DELLINK: libc::c_uint = 17;
pub const RTM_DELLINKPROP: libc::c_uint = 109;
pub const RTM_DELMDB: libc::c_uint = 85;
pub const RTM_DELNEIGH: libc::c_uint = 29;
pub const RTM_DELNETCONF: libc::c_uint = 81;
pub const RTM_DELNEXTHOP: libc::c_uint = 105;
pub const RTM_DELNEXTHOPBUCKET: libc::c_uint = 117;
pub const RTM_DELNSID: libc::c_uint = 89;
pub const RTM_DELQDISC: libc::c_uint = 37;
pub const RTM_DELROUTE: libc::c_uint = 25;
pub const RTM_DELRULE: libc::c_uint = 33;
pub const RTM_DELTCLASS: libc::c_uint = 41;
pub const RTM_DELTFILTER: libc::c_uint = 45;
pub const RTM_DELTUNNEL: libc::c_uint = 121;
pub const RTM_DELVLAN: libc::c_uint = 113;
pub const RTM_GETACTION: libc::c_uint = 50;
pub const RTM_GETADDR: libc::c_uint = 22;
pub const RTM_GETADDRLABEL: libc::c_uint = 74;
pub const RTM_GETANYCAST: libc::c_uint = 62;
pub const RTM_GETCHAIN: libc::c_uint = 102;
pub const RTM_GETDCB: libc::c_uint = 78;
pub const RTM_GETLINK: libc::c_uint = 18;
pub const RTM_GETLINKPROP: libc::c_uint = 110;
pub const RTM_GETMDB: libc::c_uint = 86;
pub const RTM_GETMULTICAST: libc::c_uint = 58;
pub const RTM_GETNEIGH: libc::c_uint = 30;
pub const RTM_GETNEIGHTBL: libc::c_uint = 66;
pub const RTM_GETNETCONF: libc::c_uint = 82;
pub const RTM_GETNEXTHOP: libc::c_uint = 106;
pub const RTM_GETNEXTHOPBUCKET: libc::c_uint = 118;
pub const RTM_GETNSID: libc::c_uint = 90;
pub const RTM_GETQDISC: libc::c_uint = 38;
pub const RTM_GETROUTE: libc::c_uint = 26;
pub const RTM_GETRULE: libc::c_uint = 34;
pub const RTM_GETSTATS: libc::c_uint = 94;
pub const RTM_GETTCLASS: libc::c_uint = 42;
pub const RTM_GETTFILTER: libc::c_uint = 46;
pub const RTM_GETTUNNEL: libc::c_uint = 122;
pub const RTM_GETVLAN: libc::c_uint = 114;
pub const RTM_NEWACTION: libc::c_uint = 48;
pub const RTM_NEWADDR: libc::c_uint = 20;
pub const RTM_NEWADDRLABEL: libc::c_uint = 72;
pub const RTM_NEWCACHEREPORT: libc::c_uint = 96;
pub const RTM_NEWCHAIN: libc::c_uint = 100;
pub const RTM_NEWLINK: libc::c_uint = 16;
pub const RTM_NEWLINKPROP: libc::c_uint = 108;
pub const RTM_NEWMDB: libc::c_uint = 84;
pub const RTM_NEWNDUSEROPT: libc::c_uint = 68;
pub const RTM_NEWNEIGH: libc::c_uint = 28;
pub const RTM_NEWNEIGHTBL: libc::c_uint = 64;
pub const RTM_NEWNETCONF: libc::c_uint = 80;
pub const RTM_NEWNEXTHOP: libc::c_uint = 104;
pub const RTM_NEWNEXTHOPBUCKET: libc::c_uint = 116;
pub const RTM_NEWNSID: libc::c_uint = 88;
pub const RTM_NEWPREFIX: libc::c_uint = 52;
pub const RTM_NEWQDISC: libc::c_uint = 36;
pub const RTM_NEWROUTE: libc::c_uint = 24;
pub const RTM_NEWRULE: libc::c_uint = 32;
pub const RTM_NEWSTATS: libc::c_uint = 92;
pub const RTM_NEWTCLASS: libc::c_uint = 40;
pub const RTM_NEWTFILTER: libc::c_uint = 44;
pub const RTM_NEWTUNNEL: libc::c_uint = 120;
pub const RTM_NEWVLAN: libc::c_uint = 112;
pub const RTM_SETDCB: libc::c_uint = 79;
pub const RTM_SETLINK: libc::c_uint = 19;
pub const RTM_SETNEIGHTBL: libc::c_uint = 67;
pub const RTM_SETSTATS: libc::c_uint = 95;
pub const SCM_PIDFD: libc::c_uint = 4;
pub const SCM_SECURITY: libc::c_uint = 3;
pub const SIZE_MAX: libc::size_t = libc::size_t::MAX;
pub const SSIZE_MAX: libc::ssize_t = libc::ssize_t::MAX;
pub const _ISalnum: libc::c_uint = 8;
pub const _ISalpha: libc::c_uint = 1024;
pub const _ISblank: libc::c_uint = 1;
pub const _IScntrl: libc::c_uint = 2;
pub const _ISdigit: libc::c_uint = 2048;
pub const _ISgraph: libc::c_uint = 32768;
pub const _ISlower: libc::c_uint = 512;
pub const _ISprint: libc::c_uint = 16384;
pub const _ISpunct: libc::c_uint = 4;
pub const _ISspace: libc::c_uint = 8192;
pub const _ISupper: libc::c_uint = 256;
pub const _ISxdigit: libc::c_uint = 4096;
pub const __IFA_MAX: libc::c_uint = 12;
pub const __NR_clone: libc::c_int = 56 as libc::c_int;
pub const __NR_pivot_root: libc::c_int = 155 as libc::c_int;
pub const __RTM_MAX: libc::c_uint = 123;
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
    pub fn get_current_dir_name() -> *mut libc::c_char;
    pub fn get_oldroot_path(path: *const libc::c_char) -> *mut libc::c_char;
    pub fn has_path_prefix(str: *const libc::c_char, prefix: *const libc::c_char) -> bool;
    pub fn load_file_at(dirfd: libc::c_int, path: *const libc::c_char) -> *mut libc::c_char;
    pub fn loopback_setup();
    pub fn mount_strerror(errsv: libc::c_int) -> *const libc::c_char;
    pub fn path_equal(path1: *const libc::c_char, path2: *const libc::c_char) -> bool;
    pub fn readlink_malloc(pathname: *const libc::c_char) -> *mut libc::c_char;
    pub fn strappendf(dest: *mut StringBuilder, fmt: *const libc::c_char, args: ...);
    pub fn xasprintf(format: *const libc::c_char, args: ...) -> *mut libc::c_char;
    pub fn xstrdup(str: *const libc::c_char) -> *mut libc::c_char;
    pub static mut stderr: *mut FILE;
    pub static mut stdout: *mut FILE;
}

pub type __socket_type = libc::c_uint;
pub type bind_option_t = libc::c_uint;
pub type bind_mount_result = libc::c_uint;
pub type MountTab = *mut MountInfo;
pub type cap_value_t = libc::c_int;
pub type cap_user_data_t = *mut __user_cap_data_struct;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct StringBuilder {
    pub str_0: *mut libc::c_char,
    pub size: size_t,
    pub offset: size_t,
}

#[inline]
pub unsafe fn steal_pointer(mut pp: *mut libc::c_void) -> *mut libc::c_void {
    let mut ptr = pp as *mut *mut libc::c_void;
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
        panic!("with_error: {:?}", std::ffi::CStr::from_ptr(v.0));
    };
}

#[macro_export]
macro_rules! die_with_bind_result {
    ($($e:expr),* $(,)?) => {
        let v = ($($e, )*);
        panic!("bind result: {:?}", (v.0));
    };
}

#[macro_export]
macro_rules! die_with_mount_error {
    ($($e:expr),* $(,)?) => {
        let v = ($($e, )*);
        panic!("with_error: {:?}", std::ffi::CStr::from_ptr(v.0));
    };
}

pub use libc::fprintf;

#[macro_export]
macro_rules! die {
    ($($e:expr),* $(,)?) => {
        let v = ($($e, )*);
        panic!("log: {:?}", std::ffi::CStr::from_ptr(v.0));
    };
}
pub const NLMSG_HDRLEN: libc::c_ulong = (::core::mem::size_of::<nlmsghdr>() as libc::c_ulong)
    .wrapping_add(NLMSG_ALIGNTO as libc::c_ulong)
    .wrapping_sub(1)
    & !NLMSG_ALIGNTO.wrapping_sub(1) as libc::c_ulong;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ifaddrmsg {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct rtattr {
    pub rta_len: libc::c_ushort,
    pub rta_type: libc::c_ushort,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ifinfomsg {
    pub ifi_family: libc::c_uchar,
    pub __ifi_pad: libc::c_uchar,
    pub ifi_type: libc::c_ushort,
    pub ifi_index: libc::c_int,
    pub ifi_flags: libc::c_uint,
    pub ifi_change: libc::c_uint,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct MountInfo {
    pub mountpoint: *mut libc::c_char,
    pub options: libc::c_ulong,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct MountInfoLine {
    pub mountpoint: *const libc::c_char,
    pub options: *const libc::c_char,
    pub covered: bool,
    pub id: libc::c_int,
    pub parent_id: libc::c_int,
    pub first_child: *mut MountInfoLine,
    pub next_sibling: *mut MountInfoLine,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct MountOptionHumanReadable {
    pub flag: libc::c_int,
    pub name: *const libc::c_char,
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

pub const _LINUX_CAPABILITY_VERSION_3: libc::c_int = 0x20080522 as libc::c_int;
pub const CAP_CHECKPOINT_RESTORE: libc::c_int = 40 as libc::c_int;
pub const CAP_LAST_CAP: libc::c_int = 40 as libc::c_int;

pub const PACKAGE_STRING: [libc::c_char; 18] =
    unsafe { *::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"bubblewrap 0.11.0\0") };
