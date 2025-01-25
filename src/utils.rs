use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use bstr::ByteSlice;
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::{Pid, SysconfVar};
use nix::NixPath;

use crate::types::*;
use crate::*;

pub fn die_unless_label_valid(mut _label: *const libc::c_char) {
    die!(c"labeling not supported on this system".as_ptr());
}

#[no_mangle]
pub extern "C" fn die_oom() -> ! {
    unsafe {
        fputs(c"Out of memory\n".as_ptr(), stderr);
        exit(1);
    }
}

pub fn fork_intermediate_child() {
    let pid = unsafe { fork() };
    if pid == -1 {
        die_with_error!(c"Can't fork for --pidns".as_ptr());
    }
    if pid != 0 {
        unsafe { exit(0) };
    }
}

pub fn xmalloc(size: size_t) -> *mut libc::c_void {
    let res = unsafe { malloc(size) };
    if res.is_null() {
        die_oom();
    }
    return res;
}

#[no_mangle]
pub extern "C" fn die_with_error_proxy(ptr: *const libc::c_char) -> ! {
    die_with_error!(ptr);
}

pub fn xcalloc(nmemb: size_t, size: size_t) -> *mut libc::c_void {
    let res = unsafe { calloc(nmemb, size) };
    if res.is_null() {
        die_oom();
    }
    return res;
}

#[no_mangle]
pub extern "C" fn xrealloc(ptr: *mut libc::c_void, size: size_t) -> *mut libc::c_void {
    assert!(size != 0);
    let res = unsafe { realloc(ptr, size) };
    if res.is_null() {
        die_oom();
    }
    return res;
}

pub fn xstrdup(str: *const libc::c_char) -> *mut libc::c_char {
    assert!(!str.is_null());
    let res = unsafe { strdup(str) };
    if res.is_null() {
        die_oom();
    }
    return res;
}

pub unsafe fn strfreev(str_array: *mut *mut libc::c_char) {
    if !str_array.is_null() {
        let mut i = 0;
        while !(*str_array.add(i)).is_null() {
            free(*str_array.add(i) as *mut libc::c_void);
            i += 1;
        }
        free(str_array as *mut libc::c_void);
    }
}

pub unsafe fn has_path_prefix(
    mut str: *const libc::c_char,
    mut prefix: *const libc::c_char,
) -> bool {
    loop {
        while *str as libc::c_int == '/' as i32 {
            str = str.offset(1);
        }
        while *prefix as libc::c_int == '/' as i32 {
            prefix = prefix.offset(1);
        }
        if *prefix as libc::c_int == 0 {
            return false;
        }
        while *prefix as libc::c_int != 0 && *prefix as libc::c_int != '/' as i32 {
            if *str as libc::c_int != *prefix as libc::c_int {
                return false;
            }
            str = str.offset(1);
            prefix = prefix.offset(1);
        }
        if *str as libc::c_int != '/' as i32 && *str as libc::c_int != 0 {
            return false;
        }
    }
}

pub unsafe fn path_equal(mut path1: *const libc::c_char, mut path2: *const libc::c_char) -> bool {
    loop {
        while *path1 == '/' as i8 {
            path1 = path1.add(1);
        }
        while *path2 == '/' as i8 {
            path2 = path2.add(1);
        }
        if *path1 == 0 || *path2 == 0 {
            return *path1 == 0 && *path2 == 0;
        }
        while *path1 != 0 && *path1 != '/' as i8 {
            if *path1 != *path2 {
                return false;
            }
            path1 = path1.add(1);
            path2 = path2.add(1);
        }
        if *path2 != '/' as i8 && *path2 != 0 {
            return false;
        }
    }
}

pub fn has_prefix(str: *const libc::c_char, prefix: *const libc::c_char) -> bool {
    return unsafe { strncmp(str, prefix, strlen(prefix)) == 0 };
}

pub fn xclearenv() {
    if unsafe { clearenv() } != 0 {
        die_with_error!(c"clearenv failed".as_ptr());
    }
}

pub fn xsetenv(name: *const libc::c_char, value: *const libc::c_char, overwrite: libc::c_int) {
    if unsafe { setenv(name, value, overwrite) } != 0 {
        die!(c"setenv failed".as_ptr());
    }
}

pub fn xunsetenv(name: *const libc::c_char) {
    if unsafe { unsetenv(name) } != 0 {
        die!(c"unsetenv failed".as_ptr());
    }
}

pub fn fdwalk<'a, F: Fn(RawFd) + 'a>(proc_fd: BorrowedFd<'_>, cb: F) -> Result<(), Errno> {
    let dfd = nix_retry!(nix::dir::Dir::openat(
        Some(proc_fd.as_raw_fd()),
        c"self/fd",
        OFlag::O_DIRECTORY
            | OFlag::O_RDONLY
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC
            | OFlag::O_NOCTTY,
        Mode::empty(),
    ));
    if let Ok(dir) = dfd {
        let dir_fd = dir.as_raw_fd();
        for entry in dir {
            let entry = entry?;
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if name.starts_with('.') {
                continue;
            }
            let Ok(l) = u64::from_str_radix(name, 10) else {
                continue;
            };
            let Ok(fd): Result<RawFd, _> = l.try_into() else {
                continue;
            };
            if fd == dir_fd {
                continue;
            }
            cb(fd);
        }
    }
    let Ok(Some(open_max)) = nix::unistd::sysconf(SysconfVar::OPEN_MAX) else {
        return Ok(());
    };
    for fd in 0..open_max {
        cb(fd as RawFd);
    }
    Ok(())
}

pub fn write_to_fd(
    fd: libc::c_int,
    mut content: *const libc::c_char,
    mut len: ssize_t,
) -> libc::c_int {
    let mut res: ssize_t = 0;
    if content.is_null() {
        return 0;
    }
    while len > 0 {
        res = unsafe { write(fd, content as *const libc::c_void, len as size_t) };
        if res < 0 && unsafe { errno!() } == libc::EINTR {
            continue;
        }
        if res <= 0 {
            if res == 0 {
                unsafe {
                    errno!() = libc::ENOSPC;
                }
            }
            return -1;
        }
        len -= res;
        content = unsafe { content.add(res as usize) };
    }
    return 0;
}

pub fn write_to_fd_rust<'fd>(
    fd: BorrowedFd<'fd>,
    mut content: &[u8],
) -> Result<(), nix::errno::Errno> {
    while !content.is_empty() {
        let res = nix_retry!(nix::unistd::write(fd, content))?;
        if res == 0 {
            return Err(nix::errno::Errno::ENOSPC);
        }
        content = &content[res..];
    }
    Ok(())
}

pub fn write_file_at_rust<P: NixPath + ?Sized>(
    dfd: Option<BorrowedFd<'_>>,
    path: &P,
    content: &[u8],
) -> Result<(), Errno> {
    let fd = nix_retry!(nix::fcntl::openat(
        dfd.map(|fd| fd.as_raw_fd()),
        path,
        OFlag::O_RDWR | OFlag::O_PATH,
        Mode::empty()
    ))
    .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })?;
    if !content.is_empty() {
        write_to_fd_rust(fd.as_fd(), content)?;
    }
    Ok(())
}

pub fn write_file_at(
    dfd: libc::c_int,
    path: *const libc::c_char,
    content: *const libc::c_char,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut res: bool = false;
    let mut errsv: libc::c_int = 0;
    fd = retry!(unsafe { openat(dfd, path, 0o2 | 0o2000000, 0) });
    if fd == -1 {
        return -1;
    }
    res = 0 != 0;
    if !content.is_null() {
        res = write_to_fd(fd, content, unsafe { strlen(content) } as ssize_t) != 0;
    }
    unsafe {
        errsv = errno!();
        close(fd);
        errno!() = errsv;
    }
    return res as libc::c_int;
}

pub fn create_file(
    path: *const libc::c_char,
    mode: mode_t,
    content: *const libc::c_char,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut res: libc::c_int = 0;
    let mut errsv: libc::c_int = 0;
    fd = retry!(unsafe { creat(path, mode) });
    if fd == -1 {
        return -1;
    }
    res = 0;
    if !content.is_null() {
        res = write_to_fd(fd, content, unsafe { strlen(content) } as ssize_t);
    }
    errsv = unsafe { errno!() };
    unsafe { close(fd) };
    unsafe {
        errno!() = errsv;
    }
    return res;
}

pub fn ensure_file(path: *const libc::c_char, mode: mode_t) -> libc::c_int {
    let mut buf: MaybeUninit<libc::stat> = MaybeUninit::uninit();
    if unsafe { stat(path, buf.as_mut_ptr()) } == 0 && {
        // SAFETY: since `stat` return 0, it means buf is populated
        let buf = unsafe { buf.assume_init() };
        !(buf.st_mode & S_IFMT as libc::c_uint == 0o40000)
            && !(buf.st_mode & S_IFMT as libc::c_uint == 0o120000)
    } {
        return 0;
    }
    if create_file(path, mode, std::ptr::null_mut()) != 0 && unsafe { errno!() != libc::EEXIST } {
        return -1;
    }
    return 0;
}

pub const BUFSIZE: usize = 8192;

pub fn copy_file_data(sfd: RawFd, dfd: RawFd) -> libc::c_int {
    let mut buffer: [libc::c_char; BUFSIZE] = [0; BUFSIZE];
    let mut bytes_read: ssize_t = 0;
    loop {
        bytes_read = unsafe { read(sfd, buffer.as_mut_ptr() as *mut libc::c_void, BUFSIZE) };
        if bytes_read == -1 {
            if unsafe { errno!() == libc::EINTR } {
                continue;
            }
            return -1;
        } else {
            if bytes_read == 0 {
                break;
            }
            if write_to_fd(dfd, buffer.as_mut_ptr(), bytes_read) != 0 {
                return -1;
            }
        }
    }
    return 0;
}

pub fn copy_file(
    src_path: *const libc::c_char,
    dst_path: *const libc::c_char,
    mode: mode_t,
) -> libc::c_int {
    let mut sfd: libc::c_int = 0;
    let mut dfd: libc::c_int = 0;
    let mut res: libc::c_int = 0;
    let mut errsv: libc::c_int = 0;
    sfd = retry!(unsafe { open(src_path, 0o2000000) });
    if sfd == -1 {
        return -1;
    }
    dfd = retry!(unsafe { creat(dst_path, mode) });
    if dfd == -1 {
        unsafe {
            errsv = errno!();
            close(sfd);
            errno!() = errsv;
        }
        return -1;
    }
    res = copy_file_data(sfd, dfd);
    unsafe {
        errsv = errno!();
        close(sfd);
        close(dfd);
        errno!() = errsv;
    }
    return res;
}

pub fn load_file_data(fd: libc::c_int, size: *mut size_t) -> *mut libc::c_char {
    let mut data = std::ptr::null_mut();
    let mut data_read: ssize_t = 0;
    let mut data_len: ssize_t = 0;
    let mut res: ssize_t = 0;
    data_read = 0;
    data_len = 4080;
    data = xmalloc(data_len as size_t) as *mut libc::c_char;
    loop {
        if data_len == data_read + 1 {
            if data_len > isize::MAX / 2 {
                unsafe { errno!() = libc::EFBIG };
                return std::ptr::null_mut();
            }
            data_len *= 2;
            data = xrealloc(data as *mut libc::c_void, data_len as size_t) as *mut libc::c_char;
        }
        loop {
            res = unsafe {
                read(
                    fd,
                    data.add(data_read as usize) as *mut libc::c_void,
                    (data_len - data_read - 1) as size_t,
                )
            };
            if !(res < 0 && unsafe { errno!() == libc::EINTR }) {
                break;
            }
        }
        if res < 0 {
            return std::ptr::null_mut();
        }
        data_read += res;
        if !(res > 0) {
            break;
        }
    }
    unsafe {
        *data.add(data_read as usize) = 0;
    }
    if !size.is_null() {
        unsafe {
            *size = data_read as size_t;
        }
    }
    return data;
}

pub fn load_file_at(dfd: libc::c_int, path: *const libc::c_char) -> *mut libc::c_char {
    let mut fd: libc::c_int = 0;
    let mut data = 0 as *mut libc::c_char;
    let mut errsv: libc::c_int = 0;
    fd = retry!(unsafe { openat(dfd, path, 0o2000000) });
    if fd == -1 {
        return std::ptr::null_mut();
    }
    data = load_file_data(fd, std::ptr::null_mut());
    unsafe {
        errsv = errno!();
        close(fd);
        errno!() = errsv;
    }
    return data;
}

pub unsafe fn get_file_mode(pathname: *const libc::c_char) -> libc::c_int {
    let mut buf: std::mem::MaybeUninit<libc::stat> = MaybeUninit::uninit();
    if stat(pathname, buf.as_mut_ptr()) != 0 {
        return -1;
    }
    let buf = buf.assume_init();
    return (buf.st_mode & S_IFMT as libc::c_uint) as libc::c_int;
}

pub unsafe fn ensure_dir(path: *const libc::c_char, mode: mode_t) -> libc::c_int {
    let mut buf: std::mem::MaybeUninit<libc::stat> = MaybeUninit::uninit();
    if stat(path, buf.as_mut_ptr()) == 0 {
        let buf = buf.assume_init();
        if !(buf.st_mode & S_IFMT as libc::c_uint == 0o40000) {
            errno!() = libc::ENOTDIR;
            return -1;
        }
        return 0;
    }
    if mkdir(path, mode) == -1 && errno!() != libc::EEXIST {
        return -1;
    }
    return 0;
}

pub unsafe fn mkdir_with_parents(
    pathname: *const libc::c_char,
    mode: mode_t,
    create_last: bool,
) -> libc::c_int {
    let mut fn_0 = std::ptr::null_mut();
    let mut p = 0 as *mut libc::c_char;
    if pathname.is_null() || *pathname as libc::c_int == '\0' as i32 {
        errno!() = libc::EINVAL;
        return -1;
    }
    fn_0 = xstrdup(pathname);
    p = fn_0;
    while *p as libc::c_int == '/' as i32 {
        p = p.offset(1);
    }
    loop {
        while *p as libc::c_int != 0 && *p as libc::c_int != '/' as i32 {
            p = p.offset(1);
        }
        if *p == 0 {
            p = std::ptr::null_mut();
        } else {
            *p = '\0' as i8;
        }
        if !create_last && p.is_null() {
            break;
        }
        if ensure_dir(fn_0, mode) != 0 {
            return -1;
        }
        if !p.is_null() {
            let fresh0 = p;
            p = p.offset(1);
            *fresh0 = '/' as i8;
            while *p as libc::c_int != 0 && *p as libc::c_int == '/' as i32 {
                p = p.offset(1);
            }
        }
        if p.is_null() {
            break;
        }
    }
    return 0;
}

pub unsafe fn send_pid_on_socket(sockfd: libc::c_int) {
    let mut buf: [libc::c_char; 1] = [0];
    let mut msg: msghdr = std::mem::zeroed();
    let mut iov = iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: ::core::mem::size_of::<[libc::c_char; 1]>(),
    };

    let control_len_snd = ((::core::mem::size_of::<ucred>() as libc::c_ulong)
        .wrapping_add(::core::mem::size_of::<size_t>() as libc::c_ulong)
        .wrapping_sub(1)
        & !(::core::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1))
    .wrapping_add(
        (::core::mem::size_of::<cmsghdr>() as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<size_t>() as libc::c_ulong)
            .wrapping_sub(1)
            & !(::core::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1),
    ) as ssize_t;
    let vla = control_len_snd as usize;
    let mut control_buf_snd: Vec<libc::c_char> = ::std::vec::from_elem(0, vla);
    let mut cmsg = std::ptr::null_mut() as *mut cmsghdr;
    let mut cred: ucred = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf_snd.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_len_snd as size_t;
    cmsg = if msg.msg_controllen >= ::core::mem::size_of::<cmsghdr>() {
        msg.msg_control as *mut cmsghdr
    } else {
        std::ptr::null_mut()
    };
    (*cmsg).cmsg_level = libc::SOL_SOCKET;
    (*cmsg).cmsg_type = libc::SCM_CREDENTIALS;
    (*cmsg).cmsg_len = ((::core::mem::size_of::<cmsghdr>())
        .wrapping_add(::core::mem::size_of::<size_t>())
        .wrapping_sub(1)
        & !(::core::mem::size_of::<size_t>()).wrapping_sub(1))
    .wrapping_add(::core::mem::size_of::<ucred>());
    cred.pid = getpid();
    cred.uid = geteuid();
    cred.gid = getegid();
    memcpy(
        libc::CMSG_DATA(cmsg) as *mut libc::c_void,
        &mut cred as *mut ucred as *const libc::c_void,
        ::core::mem::size_of::<ucred>(),
    );
    if loop {
        let __result = sendmsg(sockfd, &mut msg, 0);
        if !(__result == -1 && errno!() == libc::EINTR) {
            break __result;
        }
    } < 0
    {
        die_with_error!(c"Can't send pid".as_ptr());
    }
}

pub unsafe fn create_pid_socketpair(sockets: *mut libc::c_int) {
    let mut enable = 1;
    if socketpair(
        libc::AF_UNIX,
        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
        0,
        sockets,
    ) != 0
    {
        die_with_error!(c"Can't create intermediate pids socket".as_ptr(),);
    }
    if setsockopt(
        *sockets.offset(0),
        libc::SOL_SOCKET,
        libc::SO_PASSCRED,
        &mut enable as *mut libc::c_int as *const libc::c_void,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
    ) < 0
    {
        die_with_error!(c"Can't set SO_PASSCRED".as_ptr());
    }
}

pub unsafe fn read_pid_from_socket(sockfd: libc::c_int) -> libc::c_int {
    let mut recv_buf: [libc::c_char; 1] = [0];
    let mut msg: msghdr = std::mem::zeroed();
    let mut iov = iovec {
        iov_base: recv_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: ::core::mem::size_of::<[libc::c_char; 1]>(),
    };
    let control_len_rcv = ((::core::mem::size_of::<ucred>() as libc::c_ulong)
        .wrapping_add(::core::mem::size_of::<size_t>() as libc::c_ulong)
        .wrapping_sub(1)
        & !(::core::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1))
    .wrapping_add(
        (::core::mem::size_of::<cmsghdr>() as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<size_t>() as libc::c_ulong)
            .wrapping_sub(1)
            & !(::core::mem::size_of::<size_t>() as libc::c_ulong).wrapping_sub(1),
    ) as ssize_t;
    let vla = control_len_rcv as usize;
    let mut control_buf_rcv: Vec<libc::c_char> = ::std::vec::from_elem(0, vla);
    let mut cmsg = std::ptr::null_mut();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf_rcv.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_len_rcv as size_t;

    if retry!(recvmsg(sockfd, &raw mut msg, 0)) < 0 {
        die_with_error!(c"Can't read pid from socket".as_ptr());
    }
    if msg.msg_controllen <= 0 {
        die!(c"Unexpected short read from pid socket".as_ptr());
    }
    cmsg = if msg.msg_controllen >= ::core::mem::size_of::<cmsghdr>() {
        msg.msg_control as *mut cmsghdr
    } else {
        std::ptr::null_mut()
    };
    while !cmsg.is_null() {
        let payload_len = ((*cmsg).cmsg_len).wrapping_sub(
            ((::core::mem::size_of::<cmsghdr>())
                .wrapping_add(::core::mem::size_of::<size_t>())
                .wrapping_sub(1)
                & !(::core::mem::size_of::<size_t>()).wrapping_sub(1))
            .wrapping_add(0),
        ) as libc::c_uint;
        if (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_CREDENTIALS
            && payload_len == ::core::mem::size_of::<ucred>() as u32
        {
            let mut cred = ucred {
                pid: 0,
                uid: 0,
                gid: 0,
            };

            memcpy(
                &raw mut cred as *mut libc::c_void,
                libc::CMSG_DATA(cmsg) as *const libc::c_void,
                ::core::mem::size_of::<ucred>(),
            );
            return cred.pid;
        }
        cmsg = __cmsg_nxthdr(&mut msg, cmsg);
    }
    die!(c"No pid returned on socket".as_ptr());
}

pub unsafe fn readlink_malloc(pathname: *const libc::c_char) -> *mut libc::c_char {
    let mut size = 50;
    let mut n: ssize_t = 0;
    let mut value = std::ptr::null_mut();
    loop {
        if size > usize::MAX.wrapping_div(2) {
            die!(c"Symbolic link target pathname too long".as_ptr());
        }
        size = (size as libc::c_ulong).wrapping_mul(2) as size_t as size_t;
        value = xrealloc(value as *mut libc::c_void, size) as *mut libc::c_char;
        n = readlink(pathname, value, size.wrapping_sub(1));
        if n < 0 {
            return std::ptr::null_mut();
        }
        if !(size.wrapping_sub(2) < n as size_t) {
            break;
        }
    }
    *value.offset(n as isize) = 0;
    return (if 0 != 0 {
        value as *mut libc::c_void
    } else {
        steal_pointer(&mut value as *mut *mut libc::c_char as *mut libc::c_void)
    }) as *mut libc::c_char;
}

pub fn raw_clone(flags: nix::sched::CloneFlags) -> Result<nix::unistd::Pid, nix::errno::Errno> {
    unsafe {
        syscalls::syscall2(
            syscalls::Sysno::clone,
            std::mem::transmute::<_, _>(flags.bits() as isize),
            std::mem::transmute::<*const libc::c_void, _>(std::ptr::null()),
        )
    }
    .map(|i| Pid::from_raw(i as i32))
    .map_err(|e| nix::errno::Errno::from_raw(e.into_raw()))
}

pub fn pivot_root<P1: NixPath + ?Sized, P2: NixPath + ?Sized>(
    new_root: &P1,
    put_old: &P2,
) -> Result<(), nix::errno::Errno> {
    match new_root.with_nix_path(|new_root| {
        put_old.with_nix_path(|put_old| {
            unsafe {
                syscalls::syscall2(
                    syscalls::Sysno::pivot_root,
                    std::mem::transmute::<_, _>(new_root.as_ptr()),
                    std::mem::transmute::<_, _>(put_old.as_ptr()),
                )
            }
            .map_err(|e| nix::errno::Errno::from_raw(e.into_raw()))
        })
    }) {
        Err(e) | Ok(Err(e)) | Ok(Ok(Err(e))) => Err(e),
        Ok(Ok(Ok(_))) => Ok(()),
    }
}

pub fn mount_strerror(errsv: libc::c_int) -> *const libc::c_char {
    match errsv {
       libc::ENOSPC => c"Limit exceeded (ENOSPC). (Hint: Check that /proc/sys/fs/mount-max is sufficient, typically 100000)".as_ptr(),
        _ => unsafe {strerror(errsv)},
    }
}

#[no_mangle]
extern "C" fn xadd(a: size_t, b: size_t) -> size_t {
    if a > usize::MAX.wrapping_sub(b) {
        die_oom();
    }
    return a.wrapping_add(b);
}

#[no_mangle]
unsafe extern "C" fn xmul(a: size_t, b: size_t) -> size_t {
    if b != 0 && a > usize::MAX.wrapping_div(b) {
        die_oom();
    }
    return a.wrapping_mul(b);
}
