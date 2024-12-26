use std::os::fd::RawFd;

use crate::types::*;
use crate::*;

pub unsafe fn die_unless_label_valid(mut _label: *const libc::c_char) {
    die!(c"labeling not supported on this system".as_ptr());
}

#[no_mangle]
pub unsafe extern "C" fn die_oom() -> ! {
    fputs(c"Out of memory\n".as_ptr(), stderr);
    exit(1);
}

pub unsafe fn fork_intermediate_child() {
    let pid = fork();
    if pid == -1 {
        die_with_error!(c"Can't fork for --pidns".as_ptr());
    }
    if pid != 0 {
        exit(0);
    }
}

pub unsafe fn xmalloc(size: size_t) -> *mut libc::c_void {
    let res = malloc(size);
    if res.is_null() {
        die_oom();
    }
    return res;
}

#[no_mangle]
pub unsafe extern "C" fn die_with_error_proxy(ptr: *const libc::c_char) -> ! {
    die_with_error!(ptr);
}

pub unsafe fn xcalloc(nmemb: size_t, size: size_t) -> *mut libc::c_void {
    let res = calloc(nmemb, size);
    if res.is_null() {
        die_oom();
    }
    return res;
}

#[no_mangle]
pub unsafe extern "C" fn xrealloc(ptr: *mut libc::c_void, size: size_t) -> *mut libc::c_void {
    let mut res = 0 as *mut libc::c_void;
    assert!(size != 0);
    res = realloc(ptr, size);
    if res.is_null() {
        die_oom();
    }
    return res;
}

pub unsafe fn xstrdup(str: *const libc::c_char) -> *mut libc::c_char {
    let mut res = 0 as *mut libc::c_char;
    assert!(!str.is_null());
    res = strdup(str);
    if res.is_null() {
        die_oom();
    }
    return res;
}

pub unsafe fn strfreev(str_array: *mut *mut libc::c_char) {
    if !str_array.is_null() {
        let mut i: libc::c_int = 0;
        i = 0;
        while !(*str_array.offset(i as isize)).is_null() {
            free(*str_array.offset(i as isize) as *mut libc::c_void);
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
            return (true as i32) != 0;
        }
        while *prefix as libc::c_int != 0 && *prefix as libc::c_int != '/' as i32 {
            if *str as libc::c_int != *prefix as libc::c_int {
                return (false as i32) != 0;
            }
            str = str.offset(1);
            prefix = prefix.offset(1);
        }
        if *str as libc::c_int != '/' as i32 && *str as libc::c_int != 0 {
            return (false as i32) != 0;
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

pub unsafe fn has_prefix(str: *const libc::c_char, prefix: *const libc::c_char) -> bool {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

pub unsafe fn xclearenv() {
    if clearenv() != 0 {
        die_with_error!(c"clearenv failed".as_ptr());
    }
}

pub unsafe fn xsetenv(
    name: *const libc::c_char,
    value: *const libc::c_char,
    overwrite: libc::c_int,
) {
    if setenv(name, value, overwrite) != 0 {
        die!(c"setenv failed".as_ptr());
    }
}

pub unsafe fn xunsetenv(name: *const libc::c_char) {
    if unsetenv(name) != 0 {
        die!(c"unsetenv failed".as_ptr());
    }
}

pub unsafe fn strconcat(s1: *const libc::c_char, s2: *const libc::c_char) -> *mut libc::c_char {
    let mut len = 0 as usize;
    if !s1.is_null() {
        len += strlen(s1);
    }
    if !s2.is_null() {
        len += strlen(s2);
    }
    let res = xmalloc(len + 1) as *mut libc::c_char;

    *res = 0;
    if !s1.is_null() {
        strcat(res, s1);
    }
    if !s2.is_null() {
        strcat(res, s2);
    }

    return res;
}

pub unsafe fn strconcat3(
    s1: *const libc::c_char,
    s2: *const libc::c_char,
    s3: *const libc::c_char,
) -> *mut libc::c_char {
    let mut len = 0 as usize;
    if !s1.is_null() {
        len += strlen(s1);
    }
    if !s2.is_null() {
        len += strlen(s2);
    }
    if !s3.is_null() {
        len += strlen(s3);
    }
    let res = xmalloc(len + 1) as *mut libc::c_char;

    *res = 0;
    if !s1.is_null() {
        strcat(res, s1);
    }
    if !s2.is_null() {
        strcat(res, s2);
    }
    if !s3.is_null() {
        strcat(res, s3);
    }
    return res;
}

pub unsafe fn fdwalk(
    proc_fd: libc::c_int,
    cb: Option<unsafe fn(*mut libc::c_void, libc::c_int) -> libc::c_int>,
    data: *mut libc::c_void,
) -> libc::c_int {
    let mut open_max: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut dfd: libc::c_int = 0;
    let mut res = 0;
    let mut d = 0 as *mut DIR;
    dfd = retry!(openat(
        proc_fd,
        b"self/fd\0" as *const u8 as *const libc::c_char,
        0o200000 | 0o4000 | 0o2000000 | 0o400,
    ));
    if dfd == -1 {
        return res;
    }
    d = fdopendir(dfd);
    if !d.is_null() {
        let mut de = 0 as *mut libc::dirent;
        loop {
            de = readdir(d);
            if de.is_null() {
                break;
            }
            let mut l: libc::c_long = 0;
            let mut e = std::ptr::null_mut();
            if (*de).d_name[0] as libc::c_int == '.' as i32 {
                continue;
            }
            errno!() = 0;
            l = strtol(((*de).d_name).as_mut_ptr(), &mut e, 10);
            if errno!() != 0 || e.is_null() || *e as libc::c_int != 0 {
                continue;
            }
            fd = l as libc::c_int;
            if fd as libc::c_long != l {
                continue;
            }
            if fd == dirfd(d) {
                continue;
            }
            res = cb.expect("non-null function pointer")(data, fd);
            if res != 0 {
                break;
            }
        }
        closedir(d);
        return res;
    }
    open_max = sysconf(libc::_SC_OPEN_MAX) as libc::c_int;
    fd = 0;
    while fd < open_max {
        res = cb.expect("non-null function pointer")(data, fd);
        if res != 0 {
            break;
        }
        fd += 1;
    }
    return res;
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
        if res < 0 && unsafe { errno!() } == EINTR {
            continue;
        }
        if res <= 0 {
            if res == 0 {
                unsafe {
                    errno!() = ENOSPC;
                }
            }
            return -1;
        }
        len -= res;
        content = unsafe { content.add(res as usize) };
    }
    return 0;
}

pub unsafe fn write_file_at(
    dfd: libc::c_int,
    path: *const libc::c_char,
    content: *const libc::c_char,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut res: bool = false;
    let mut errsv: libc::c_int = 0;
    fd = retry!(openat(dfd, path, 0o2 | 0o2000000, 0));
    if fd == -1 {
        return -1;
    }
    res = 0 != 0;
    if !content.is_null() {
        res = write_to_fd(fd, content, strlen(content) as ssize_t) != 0;
    }
    errsv = errno!();
    close(fd);
    errno!() = errsv;
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
    if create_file(path, mode, std::ptr::null_mut()) != 0 && unsafe { errno!() != EEXIST } {
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
            if unsafe { errno!() == EINTR } {
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
    data = unsafe { xmalloc(data_len as size_t) as *mut libc::c_char };
    loop {
        if data_len == data_read + 1 {
            if data_len > SSIZE_MAX / 2 {
                unsafe { errno!() = EFBIG };
                return std::ptr::null_mut();
            }
            data_len *= 2;
            data = unsafe {
                xrealloc(data as *mut libc::c_void, data_len as size_t) as *mut libc::c_char
            };
        }
        loop {
            res = unsafe {
                read(
                    fd,
                    data.add(data_read as usize) as *mut libc::c_void,
                    (data_len - data_read - 1) as size_t,
                )
            };
            if !(res < 0 && unsafe { errno!() == EINTR }) {
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
            errno!() = ENOTDIR;
            return -1;
        }
        return 0;
    }
    if mkdir(path, mode) == -1 && errno!() != EEXIST {
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
        errno!() = EINVAL;
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
        if !(__result == -1 && errno!() == EINTR) {
            break __result;
        }
    } < 0
    {
        die_with_error!(b"Can't send pid\0" as *const u8 as *const libc::c_char);
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
        die_with_error!(
            b"Can't create intermediate pids socket\0" as *const u8 as *const libc::c_char,
        );
    }
    if setsockopt(
        *sockets.offset(0),
        libc::SOL_SOCKET,
        libc::SO_PASSCRED,
        &mut enable as *mut libc::c_int as *const libc::c_void,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
    ) < 0
    {
        die_with_error!(b"Can't set SO_PASSCRED\0" as *const u8 as *const libc::c_char);
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
    if loop {
        let __result = recvmsg(sockfd, &raw mut msg, 0);
        if !(__result == -1 && errno!() == EINTR) {
            break __result;
        }
    } < 0
    {
        die_with_error!(b"Can't read pid from socket\0" as *const u8 as *const libc::c_char);
    }
    if msg.msg_controllen <= 0 {
        die!(b"Unexpected short read from pid socket\0" as *const u8 as *const libc::c_char);
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
    die!(b"No pid returned on socket\0" as *const u8 as *const libc::c_char);
}

pub unsafe fn readlink_malloc(pathname: *const libc::c_char) -> *mut libc::c_char {
    let mut size = 50;
    let mut n: ssize_t = 0;
    let mut value = std::ptr::null_mut();
    loop {
        if size > SIZE_MAX.wrapping_div(2) {
            die!(b"Symbolic link target pathname too long\0" as *const u8 as *const libc::c_char);
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

pub unsafe fn get_oldroot_path(mut path: *const libc::c_char) -> *mut libc::c_char {
    while *path as libc::c_int == '/' as i32 {
        path = path.offset(1);
    }
    return strconcat(b"/oldroot/\0" as *const u8 as *const libc::c_char, path);
}

pub unsafe fn get_newroot_path(mut path: *const libc::c_char) -> *mut libc::c_char {
    while *path as libc::c_int == '/' as i32 {
        path = path.offset(1);
    }
    return strconcat(b"/newroot/\0" as *const u8 as *const libc::c_char, path);
}

pub unsafe fn raw_clone(flags: libc::c_ulong, child_stack: *mut libc::c_void) -> libc::c_int {
    return syscall(__NR_clone as libc::c_long, flags, child_stack) as libc::c_int;
}

pub unsafe fn pivot_root(
    new_root: *const libc::c_char,
    put_old: *const libc::c_char,
) -> libc::c_int {
    return syscall(__NR_pivot_root as libc::c_long, new_root, put_old) as libc::c_int;
}

pub unsafe fn label_mount(
    opt: *const libc::c_char,
    mut _mount_label: *const libc::c_char,
) -> *mut libc::c_char {
    if !opt.is_null() {
        return xstrdup(opt);
    }
    return std::ptr::null_mut();
}

pub unsafe fn label_create_file(mut _file_label: *const libc::c_char) -> libc::c_int {
    return 0;
}

pub unsafe fn label_exec(mut _exec_label: *const libc::c_char) -> libc::c_int {
    return 0;
}

pub unsafe fn mount_strerror(errsv: libc::c_int) -> *const libc::c_char {
    match errsv {
        ENOSPC => c"Limit exceeded (ENOSPC). (Hint: Check that /proc/sys/fs/mount-max is sufficient, typically 100000)".as_ptr(),
        _ => strerror(errsv),
    }
}

#[no_mangle]
unsafe extern "C" fn xadd(a: size_t, b: size_t) -> size_t {
    if a > SIZE_MAX.wrapping_sub(b) {
        die_oom();
    }
    return a.wrapping_add(b);
}

#[no_mangle]
unsafe extern "C" fn xmul(a: size_t, b: size_t) -> size_t {
    if b != 0 && a > SIZE_MAX.wrapping_div(b) {
        die_oom();
    }
    return a.wrapping_mul(b);
}

pub unsafe fn strappend(dest: *mut StringBuilder, src: *const libc::c_char) {
    let len = strlen(src);
    let new_offset = xadd((*dest).offset, len);
    if new_offset >= (*dest).size {
        (*dest).size = xmul(xadd(new_offset, 1), 2);
        (*dest).str_0 =
            xrealloc((*dest).str_0 as *mut libc::c_void, (*dest).size) as *mut libc::c_char;
    }
    strncpy(
        ((*dest).str_0).offset((*dest).offset as isize),
        src,
        len.wrapping_add(1),
    );
    (*dest).offset = new_offset;
}

pub unsafe fn strappend_escape_for_mount_options(
    dest: *mut StringBuilder,
    mut src: *const libc::c_char,
) {
    let mut unescaped = true;
    loop {
        if (*dest).offset == (*dest).size {
            (*dest).size = if 64 > xmul((*dest).size, 2) {
                64
            } else {
                xmul((*dest).size, 2)
            };
            (*dest).str_0 =
                xrealloc((*dest).str_0 as *mut libc::c_void, (*dest).size) as *mut libc::c_char;
        }
        match *src as libc::c_int {
            0 => {
                *((*dest).str_0).offset((*dest).offset as isize) = '\0' as i8;
                return;
            }
            92 | 44 | 58 => {
                if unescaped {
                    let fresh1 = (*dest).offset as isize;
                    (*dest).offset = ((*dest).offset).wrapping_add(1);
                    *((*dest).str_0).offset(fresh1) = '\\' as i8;
                    unescaped = false;
                    continue;
                }
            }
            _ => {}
        }
        let fresh2 = (*dest).offset as isize;
        (*dest).offset = ((*dest).offset).wrapping_add(1);
        *((*dest).str_0).offset(fresh2) = *src;
        unescaped = true;
        src = src.offset(1);
    }
}
