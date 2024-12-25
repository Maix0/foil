use crate::types::*;
use crate::*;

#[no_mangle]
pub unsafe extern "C" fn die_unless_label_valid(mut label: *const libc::c_char) {
    die!(b"labeling not supported on this system\0" as *const u8 as *const libc::c_char);
}
#[no_mangle]

pub unsafe extern "C" fn die_oom() -> ! {
    fputs(
        b"Out of memory\n\0" as *const u8 as *const libc::c_char,
        stderr,
    );
    exit(1 as libc::c_int);
}
#[no_mangle]

pub unsafe extern "C" fn fork_intermediate_child() {
    let mut pid = fork();
    if pid == -(1 as libc::c_int) {
        die_with_error!(b"Can't fork for --pidns\0" as *const u8 as *const libc::c_char);
    }
    if pid != 0 as libc::c_int {
        exit(0 as libc::c_int);
    }
}
#[no_mangle]

pub unsafe extern "C" fn xmalloc(mut size: size_t) -> *mut libc::c_void {
    let mut res = malloc(size);
    if res.is_null() {
        die_oom();
    }
    return res;
}
#[no_mangle]

pub unsafe extern "C" fn xcalloc(mut nmemb: size_t, mut size: size_t) -> *mut libc::c_void {
    let mut res = calloc(nmemb, size);
    if res.is_null() {
        die_oom();
    }
    return res;
}
#[no_mangle]

pub unsafe extern "C" fn xrealloc(
    mut ptr: *mut libc::c_void,
    mut size: size_t,
) -> *mut libc::c_void {
    let mut res = 0 as *mut libc::c_void;
    assert!(size != 0);
    res = realloc(ptr, size);
    if res.is_null() {
        die_oom();
    }
    return res;
}
#[no_mangle]

pub unsafe extern "C" fn xstrdup(mut str: *const libc::c_char) -> *mut libc::c_char {
    let mut res = 0 as *mut libc::c_char;
    assert!(!str.is_null());
    res = strdup(str);
    if res.is_null() {
        die_oom();
    }
    return res;
}
#[no_mangle]

pub unsafe extern "C" fn strfreev(mut str_array: *mut *mut libc::c_char) {
    if !str_array.is_null() {
        let mut i: libc::c_int = 0;
        i = 0 as libc::c_int;
        while !(*str_array.offset(i as isize)).is_null() {
            free(*str_array.offset(i as isize) as *mut libc::c_void);
            i += 1;
            i;
        }
        free(str_array as *mut libc::c_void);
    }
}
#[no_mangle]

pub unsafe extern "C" fn has_path_prefix(
    mut str: *const libc::c_char,
    mut prefix: *const libc::c_char,
) -> bool {
    loop {
        while *str as libc::c_int == '/' as i32 {
            str = str.offset(1);
            str;
        }
        while *prefix as libc::c_int == '/' as i32 {
            prefix = prefix.offset(1);
            prefix;
        }
        if *prefix as libc::c_int == 0 as libc::c_int {
            return (true as i32) != 0;
        }
        while *prefix as libc::c_int != 0 as libc::c_int && *prefix as libc::c_int != '/' as i32 {
            if *str as libc::c_int != *prefix as libc::c_int {
                return (false as i32) != 0;
            }
            str = str.offset(1);
            str;
            prefix = prefix.offset(1);
            prefix;
        }
        if *str as libc::c_int != '/' as i32 && *str as libc::c_int != 0 as libc::c_int {
            return (false as i32) != 0;
        }
    }
}
#[no_mangle]

pub unsafe extern "C" fn path_equal(
    mut path1: *const libc::c_char,
    mut path2: *const libc::c_char,
) -> bool {
    loop {
        while *path1 as libc::c_int == '/' as i32 {
            path1 = path1.offset(1);
        }
        while *path2 as libc::c_int == '/' as i32 {
            path2 = path2.offset(1);
        }
        if *path1 as libc::c_int == 0 as libc::c_int || *path2 as libc::c_int == 0 as libc::c_int {
            return *path1 as libc::c_int == 0 as libc::c_int
                && *path2 as libc::c_int == 0 as libc::c_int;
        }
        while *path1 as libc::c_int != 0 as libc::c_int && *path1 as libc::c_int != '/' as i32 {
            if *path1 as libc::c_int != *path2 as libc::c_int {
                return (false as i32) != 0;
            }
            path1 = path1.offset(1);
            path2 = path2.offset(1);
        }
        if *path2 as libc::c_int != '/' as i32 && *path2 as libc::c_int != 0 as libc::c_int {
            return (false as i32) != 0;
        }
    }
}
#[no_mangle]

pub unsafe extern "C" fn has_prefix(
    mut str: *const libc::c_char,
    mut prefix: *const libc::c_char,
) -> bool {
    return strncmp(str, prefix, strlen(prefix)) == 0 as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn xclearenv() {
    if clearenv() != 0 as libc::c_int {
        die_with_error!(b"clearenv failed\0" as *const u8 as *const libc::c_char);
    }
}
#[no_mangle]

pub unsafe extern "C" fn xsetenv(
    mut name: *const libc::c_char,
    mut value: *const libc::c_char,
    mut overwrite: libc::c_int,
) {
    if setenv(name, value, overwrite) != 0 {
        panic!("setenv failed");
    }
}
#[no_mangle]

pub unsafe extern "C" fn xunsetenv(mut name: *const libc::c_char) {
    if unsetenv(name) != 0 {
        panic!("unsetenv failed");
    }
}
#[no_mangle]
pub unsafe extern "C" fn strconcat(
    mut s1: *const libc::c_char,
    mut s2: *const libc::c_char,
) -> *mut libc::c_char {
    let mut len = 0 as libc::c_int as size_t;
    let mut res = 0 as *mut libc::c_char;
    if !s1.is_null() {
        len = (len).wrapping_add(strlen(s1)) as size_t as size_t;
    }
    if !s2.is_null() {
        len = (len).wrapping_add(strlen(s2)) as size_t as size_t;
    }
    res = xmalloc(len.wrapping_add(1)) as *mut libc::c_char;
    *res = 0 as libc::c_int as libc::c_char;
    if !s1.is_null() {
        strcat(res, s1);
    }
    if !s2.is_null() {
        strcat(res, s2);
    }
    return res;
}

#[no_mangle]
pub unsafe extern "C" fn strconcat3(
    mut s1: *const libc::c_char,
    mut s2: *const libc::c_char,
    mut s3: *const libc::c_char,
) -> *mut libc::c_char {
    let mut len = 0 as libc::c_int as size_t;
    let mut res = 0 as *mut libc::c_char;
    if !s1.is_null() {
        len = (len).wrapping_add(strlen(s1));
    }
    if !s2.is_null() {
        len = (len).wrapping_add(strlen(s2));
    }
    if !s3.is_null() {
        len = (len).wrapping_add(strlen(s3));
    }
    res = xmalloc(len.wrapping_add(1)) as *mut libc::c_char;
    *res = 0 as libc::c_int as libc::c_char;
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

#[no_mangle]
pub unsafe extern "C" fn fdwalk(
    mut proc_fd: libc::c_int,
    mut cb: Option<unsafe extern "C" fn(*mut libc::c_void, libc::c_int) -> libc::c_int>,
    mut data: *mut libc::c_void,
) -> libc::c_int {
    let mut open_max: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut dfd: libc::c_int = 0;
    let mut res = 0 as libc::c_int;
    let mut d = 0 as *mut DIR;
    dfd = ({
        let mut __result: libc::c_long = 0;
        loop {
            __result = openat(
                proc_fd,
                b"self/fd\0" as *const u8 as *const libc::c_char,
                0o200000 as libc::c_int
                    | 0o4000 as libc::c_int
                    | 0o2000000 as libc::c_int
                    | 0o400 as libc::c_int,
            ) as libc::c_long;
            if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                break;
            }
        }
        __result
    }) as libc::c_int;
    if dfd == -(1 as libc::c_int) {
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
            if (*de).d_name[0 as libc::c_int as usize] as libc::c_int == '.' as i32 {
                continue;
            }
            errno!() = 0 as libc::c_int;
            l = strtol(((*de).d_name).as_mut_ptr(), &mut e, 10 as libc::c_int);
            if errno!() != 0 as libc::c_int || e.is_null() || *e as libc::c_int != 0 {
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
            if res != 0 as libc::c_int {
                break;
            }
        }
        closedir(d);
        return res;
    }
    open_max = sysconf(libc::_SC_OPEN_MAX) as libc::c_int;
    fd = 0 as libc::c_int;
    while fd < open_max {
        res = cb.expect("non-null function pointer")(data, fd);
        if res != 0 as libc::c_int {
            break;
        }
        fd += 1;
        fd;
    }
    return res;
}
#[no_mangle]

pub unsafe extern "C" fn write_to_fd(
    mut fd: libc::c_int,
    mut content: *const libc::c_char,
    mut len: ssize_t,
) -> libc::c_int {
    let mut res: ssize_t = 0;
    while len > 0 {
        res = write(fd, content as *const libc::c_void, len as size_t);
        if res < 0 && errno!() == EINTR {
            continue;
        }
        if res <= 0 {
            if res == 0 {
                errno!() = ENOSPC;
            }
            return -(1 as libc::c_int);
        }
        len -= res;
        content = content.offset(res as isize);
    }
    return 0 as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn write_file_at(
    mut dfd: libc::c_int,
    mut path: *const libc::c_char,
    mut content: *const libc::c_char,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut res: bool = false;
    let mut errsv: libc::c_int = 0;
    fd = ({
        let mut __result: libc::c_long = 0;
        loop {
            __result = openat(
                dfd,
                path,
                0o2 as libc::c_int | 0o2000000 as libc::c_int,
                0 as libc::c_int,
            ) as libc::c_long;
            if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                break;
            }
        }
        __result
    }) as libc::c_int;
    if fd == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    res = 0 as libc::c_int != 0;
    if !content.is_null() {
        res = write_to_fd(fd, content, strlen(content) as ssize_t) != 0;
    }
    errsv = errno!();
    close(fd);
    errno!() = errsv;
    return res as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn create_file(
    mut path: *const libc::c_char,
    mut mode: mode_t,
    mut content: *const libc::c_char,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut res: libc::c_int = 0;
    let mut errsv: libc::c_int = 0;
    fd = ({
        let mut __result: libc::c_long = 0;
        loop {
            __result = creat(path, mode) as libc::c_long;
            if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                break;
            }
        }
        __result
    }) as libc::c_int;
    if fd == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    res = 0 as libc::c_int;
    if !content.is_null() {
        res = write_to_fd(fd, content, strlen(content) as ssize_t);
    }
    errsv = errno!();
    close(fd);
    errno!() = errsv;
    return res;
}
#[no_mangle]

pub unsafe extern "C" fn ensure_file(
    mut path: *const libc::c_char,
    mut mode: mode_t,
) -> libc::c_int {
    let mut buf: MaybeUninit<libc::stat> = MaybeUninit::uninit();
    if stat(path, buf.as_mut_ptr()) == 0 && {
        let buf = buf.assume_init();
        !(buf.st_mode & S_IFMT as libc::c_uint == 0o40000 as libc::c_int as libc::c_uint)
            && !(buf.st_mode & S_IFMT as libc::c_uint == 0o120000 as libc::c_int as libc::c_uint)
    } {
        return 0;
    }
    if create_file(path, mode, std::ptr::null_mut()) != 0 as libc::c_int && errno!() != EEXIST {
        return -1;
    }
    return 0;
}

pub const BUFSIZE: libc::c_int = 8192 as libc::c_int;
#[no_mangle]

pub unsafe extern "C" fn copy_file_data(mut sfd: libc::c_int, mut dfd: libc::c_int) -> libc::c_int {
    let mut buffer: [libc::c_char; 8192] = [0; 8192];
    let mut bytes_read: ssize_t = 0;
    loop {
        bytes_read = read(
            sfd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            BUFSIZE as size_t,
        );
        if bytes_read == -1 {
            if errno!() == EINTR {
                continue;
            }
            return -(1 as libc::c_int);
        } else {
            if bytes_read == 0 {
                break;
            }
            if write_to_fd(dfd, buffer.as_mut_ptr(), bytes_read) != 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn copy_file(
    mut src_path: *const libc::c_char,
    mut dst_path: *const libc::c_char,
    mut mode: mode_t,
) -> libc::c_int {
    let mut sfd: libc::c_int = 0;
    let mut dfd: libc::c_int = 0;
    let mut res: libc::c_int = 0;
    let mut errsv: libc::c_int = 0;
    sfd = loop {
        let __result = open(src_path, 0o2000000);
        if !(__result == -1 && errno!() == EINTR) {
            break __result;
        }
    } as libc::c_int;
    if sfd == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    dfd = ({
        let mut __result: libc::c_long = 0;
        loop {
            __result = creat(dst_path, mode) as libc::c_long;
            if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                break;
            }
        }
        __result
    }) as libc::c_int;
    if dfd == -(1 as libc::c_int) {
        errsv = errno!();
        close(sfd);
        errno!() = errsv;
        return -(1 as libc::c_int);
    }
    res = copy_file_data(sfd, dfd);
    errsv = errno!();
    close(sfd);
    close(dfd);
    errno!() = errsv;
    return res;
}
#[no_mangle]

pub unsafe extern "C" fn load_file_data(
    mut fd: libc::c_int,
    mut size: *mut size_t,
) -> *mut libc::c_char {
    let mut data = std::ptr::null_mut();
    let mut data_read: ssize_t = 0;
    let mut data_len: ssize_t = 0;
    let mut res: ssize_t = 0;
    data_read = 0 as libc::c_int as ssize_t;
    data_len = 4080 as libc::c_int as ssize_t;
    data = xmalloc(data_len as size_t) as *mut libc::c_char;
    loop {
        if data_len == data_read + 1 {
            if data_len > SSIZE_MAX / 2 {
                errno!() = EFBIG;
                return std::ptr::null_mut();
            }
            data_len *= 2;
            data = xrealloc(data as *mut libc::c_void, data_len as size_t) as *mut libc::c_char;
        }
        loop {
            res = read(
                fd,
                data.offset(data_read as isize) as *mut libc::c_void,
                (data_len - data_read - 1) as size_t,
            );
            if !(res < 0 && errno!() == EINTR) {
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
    *data.offset(data_read as isize) = 0 as libc::c_int as libc::c_char;
    if !size.is_null() {
        *size = data_read as size_t;
    }
    return (if 0 != 0 {
        data as *mut libc::c_void
    } else {
        steal_pointer(&mut data as *mut *mut libc::c_char as *mut libc::c_void)
    }) as *mut libc::c_char;
}
#[no_mangle]

pub unsafe extern "C" fn load_file_at(
    mut dfd: libc::c_int,
    mut path: *const libc::c_char,
) -> *mut libc::c_char {
    let mut fd: libc::c_int = 0;
    let mut data = 0 as *mut libc::c_char;
    let mut errsv: libc::c_int = 0;
    fd = ({
        let mut __result: libc::c_long = 0;
        loop {
            __result =
                openat(dfd, path, 0o2000000 as libc::c_int | 0 as libc::c_int) as libc::c_long;
            if !(__result == -(1 as libc::c_long) && errno!() == EINTR) {
                break;
            }
        }
        __result
    }) as libc::c_int;
    if fd == -(1 as libc::c_int) {
        return std::ptr::null_mut();
    }
    data = load_file_data(fd, std::ptr::null_mut());
    errsv = errno!();
    close(fd);
    errno!() = errsv;
    return data;
}
#[no_mangle]

pub unsafe extern "C" fn get_file_mode(mut pathname: *const libc::c_char) -> libc::c_int {
    let mut buf: std::mem::MaybeUninit<libc::stat> = MaybeUninit::uninit();
    if stat(pathname, buf.as_mut_ptr()) != 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    let buf = buf.assume_init();
    return (buf.st_mode & S_IFMT as libc::c_uint) as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn ensure_dir(
    mut path: *const libc::c_char,
    mut mode: mode_t,
) -> libc::c_int {
    let mut buf: std::mem::MaybeUninit<libc::stat> = MaybeUninit::uninit();
    if stat(path, buf.as_mut_ptr()) == 0 {
        let buf = buf.assume_init();
        if !(buf.st_mode & S_IFMT as libc::c_uint == 0o40000 as libc::c_int as libc::c_uint) {
            errno!() = ENOTDIR;
            return -(1);
        }
        return 0;
    }
    if mkdir(path, mode) == -(1 as libc::c_int) && errno!() != EEXIST {
        return -(1);
    }
    return 0;
}
#[no_mangle]

pub unsafe extern "C" fn mkdir_with_parents(
    mut pathname: *const libc::c_char,
    mut mode: mode_t,
    mut create_last: bool,
) -> libc::c_int {
    let mut fn_0 = std::ptr::null_mut();
    let mut p = 0 as *mut libc::c_char;
    if pathname.is_null() || *pathname as libc::c_int == '\0' as i32 {
        errno!() = EINVAL;
        return -(1 as libc::c_int);
    }
    fn_0 = xstrdup(pathname);
    p = fn_0;
    while *p as libc::c_int == '/' as i32 {
        p = p.offset(1);
        p;
    }
    loop {
        while *p as libc::c_int != 0 && *p as libc::c_int != '/' as i32 {
            p = p.offset(1);
            p;
        }
        if *p == 0 {
            p = std::ptr::null_mut();
        } else {
            *p = '\0' as i32 as libc::c_char;
        }
        if !create_last && p.is_null() {
            break;
        }
        if ensure_dir(fn_0, mode) != 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if !p.is_null() {
            let fresh0 = p;
            p = p.offset(1);
            *fresh0 = '/' as i32 as libc::c_char;
            while *p as libc::c_int != 0 && *p as libc::c_int == '/' as i32 {
                p = p.offset(1);
                p;
            }
        }
        if p.is_null() {
            break;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn send_pid_on_socket(mut sockfd: libc::c_int) {
    let mut buf: [libc::c_char; 1] = [0 as libc::c_int as libc::c_char];
    let mut msg = {
        let mut init = msghdr {
            msg_name: 0 as *mut libc::c_void,
            msg_namelen: 0,
            msg_iov: 0 as *mut iovec,
            msg_iovlen: 0,
            msg_control: 0 as *mut libc::c_void,
            msg_controllen: 0,
            msg_flags: 0,
        };
        init
    };
    let mut iov = {
        let mut init = iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: ::core::mem::size_of::<[libc::c_char; 1]>(),
        };
        init
    };
    let control_len_snd = ((::core::mem::size_of::<ucred>() as libc::c_ulong)
        .wrapping_add(::core::mem::size_of::<size_t>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        & !(::core::mem::size_of::<size_t>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong))
    .wrapping_add(
        (::core::mem::size_of::<cmsghdr>() as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<size_t>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            & !(::core::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    ) as ssize_t;
    let vla = control_len_snd as usize;
    let mut control_buf_snd: Vec<libc::c_char> = ::std::vec::from_elem(0, vla);
    let mut cmsg = 0 as *mut cmsghdr;
    let mut cred = ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1 as libc::c_int as size_t;
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
    if (loop {
        let __result = sendmsg(sockfd, &mut msg, 0);
        if !(__result == -(1) && errno!() == EINTR) {
            break __result;
        }
    }) < 0
    {
        die_with_error!(b"Can't send pid\0" as *const u8 as *const libc::c_char);
    }
}
#[no_mangle]

pub unsafe extern "C" fn create_pid_socketpair(mut sockets: *mut libc::c_int) {
    let mut enable = 1 as libc::c_int;
    if socketpair(
        libc::AF_UNIX,
        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
        0 as libc::c_int,
        sockets,
    ) != 0 as libc::c_int
    {
        die_with_error!(
            b"Can't create intermediate pids socket\0" as *const u8 as *const libc::c_char,
        );
    }
    if setsockopt(
        *sockets.offset(0 as libc::c_int as isize),
        libc::SOL_SOCKET,
        libc::SO_PASSCRED,
        &mut enable as *mut libc::c_int as *const libc::c_void,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
    ) < 0 as libc::c_int
    {
        die_with_error!(b"Can't set SO_PASSCRED\0" as *const u8 as *const libc::c_char);
    }
}
#[no_mangle]

pub unsafe extern "C" fn read_pid_from_socket(mut sockfd: libc::c_int) -> libc::c_int {
    let mut recv_buf: [libc::c_char; 1] = [0 as libc::c_int as libc::c_char];
    let mut msg = msghdr {
        msg_name: 0 as *mut libc::c_void,
        msg_namelen: 0,
        msg_iov: 0 as *mut iovec,
        msg_iovlen: 0,
        msg_control: 0 as *mut libc::c_void,
        msg_controllen: 0,
        msg_flags: 0,
    };
    let mut iov = iovec {
        iov_base: recv_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: ::core::mem::size_of::<[libc::c_char; 1]>(),
    };
    let control_len_rcv = ((::core::mem::size_of::<ucred>() as libc::c_ulong)
        .wrapping_add(::core::mem::size_of::<size_t>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        & !(::core::mem::size_of::<size_t>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong))
    .wrapping_add(
        (::core::mem::size_of::<cmsghdr>() as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<size_t>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            & !(::core::mem::size_of::<size_t>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    ) as ssize_t;
    let vla = control_len_rcv as usize;
    let mut control_buf_rcv: Vec<libc::c_char> = ::std::vec::from_elem(0, vla);
    let mut cmsg = std::ptr::null_mut();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1 as libc::c_int as size_t;
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
#[no_mangle]

pub unsafe extern "C" fn readlink_malloc(mut pathname: *const libc::c_char) -> *mut libc::c_char {
    let mut size = 50 as size_t;
    let mut n: ssize_t = 0;
    let mut value = std::ptr::null_mut();
    loop {
        if size > SIZE_MAX.wrapping_div(2) {
            die!(b"Symbolic link target pathname too long\0" as *const u8 as *const libc::c_char);
        }
        size = (size as libc::c_ulong).wrapping_mul(2 as libc::c_int as libc::c_ulong) as size_t
            as size_t;
        value = xrealloc(value as *mut libc::c_void, size) as *mut libc::c_char;
        n = readlink(pathname, value, size.wrapping_sub(1));
        if n < 0 {
            return std::ptr::null_mut();
        }
        if !(size.wrapping_sub(2) < n as size_t) {
            break;
        }
    }
    *value.offset(n as isize) = 0 as libc::c_int as libc::c_char;
    return (if 0 as libc::c_int != 0 {
        value as *mut libc::c_void
    } else {
        steal_pointer(&mut value as *mut *mut libc::c_char as *mut libc::c_void)
    }) as *mut libc::c_char;
}
#[no_mangle]

pub unsafe extern "C" fn get_oldroot_path(mut path: *const libc::c_char) -> *mut libc::c_char {
    while *path as libc::c_int == '/' as i32 {
        path = path.offset(1);
        path;
    }
    return strconcat(b"/oldroot/\0" as *const u8 as *const libc::c_char, path);
}
#[no_mangle]

pub unsafe extern "C" fn get_newroot_path(mut path: *const libc::c_char) -> *mut libc::c_char {
    while *path as libc::c_int == '/' as i32 {
        path = path.offset(1);
        path;
    }
    return strconcat(b"/newroot/\0" as *const u8 as *const libc::c_char, path);
}
#[no_mangle]

pub unsafe extern "C" fn raw_clone(
    mut flags: libc::c_ulong,
    mut child_stack: *mut libc::c_void,
) -> libc::c_int {
    return syscall(__NR_clone as libc::c_long, flags, child_stack) as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn pivot_root(
    mut new_root: *const libc::c_char,
    mut put_old: *const libc::c_char,
) -> libc::c_int {
    return syscall(__NR_pivot_root as libc::c_long, new_root, put_old) as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn label_mount(
    mut opt: *const libc::c_char,
    mut mount_label: *const libc::c_char,
) -> *mut libc::c_char {
    if !opt.is_null() {
        return xstrdup(opt);
    }
    return std::ptr::null_mut();
}
#[no_mangle]

pub unsafe extern "C" fn label_create_file(mut file_label: *const libc::c_char) -> libc::c_int {
    return 0 as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn label_exec(mut exec_label: *const libc::c_char) -> libc::c_int {
    return 0 as libc::c_int;
}
#[no_mangle]

pub unsafe extern "C" fn mount_strerror(mut errsv: libc::c_int) -> *const libc::c_char {
    match errsv {
        ENOSPC => {
            return b"Limit exceeded (ENOSPC). (Hint: Check that /proc/sys/fs/mount-max is sufficient, typically 100000)\0"
                as *const u8 as *const libc::c_char;
        }
        _ => return strerror(errsv),
    };
}

unsafe extern "C" fn xadd(mut a: size_t, mut b: size_t) -> size_t {
    if a > SIZE_MAX.wrapping_sub(b) {
        die_oom();
    }
    return a.wrapping_add(b);
}

unsafe extern "C" fn xmul(mut a: size_t, mut b: size_t) -> size_t {
    if b != 0 && a > SIZE_MAX.wrapping_div(b) {
        die_oom();
    }
    return a.wrapping_mul(b);
}
#[no_mangle]

pub unsafe extern "C" fn strappend(mut dest: *mut StringBuilder, mut src: *const libc::c_char) {
    let mut len = strlen(src);
    let mut new_offset = xadd((*dest).offset, len);
    if new_offset >= (*dest).size {
        (*dest).size = xmul(
            xadd(new_offset, 1 as libc::c_int as size_t),
            2 as libc::c_int as size_t,
        );
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

#[no_mangle]
pub unsafe extern "C" fn strappend_escape_for_mount_options(
    mut dest: *mut StringBuilder,
    mut src: *const libc::c_char,
) {
    let mut unescaped = true;
    loop {
        if (*dest).offset == (*dest).size {
            (*dest).size = if 64 > xmul((*dest).size, 2) {
                64
            } else {
                xmul((*dest).size, 2 as libc::c_int as size_t)
            };
            (*dest).str_0 =
                xrealloc((*dest).str_0 as *mut libc::c_void, (*dest).size) as *mut libc::c_char;
        }
        match *src as libc::c_int {
            0 => {
                *((*dest).str_0).offset((*dest).offset as isize) = '\0' as i32 as libc::c_char;
                return;
            }
            92 | 44 | 58 => {
                if unescaped {
                    let fresh1 = (*dest).offset;
                    (*dest).offset = ((*dest).offset).wrapping_add(1);
                    *((*dest).str_0).offset(fresh1 as isize) = '\\' as i32 as libc::c_char;
                    unescaped = false;
                    continue;
                }
            }
            _ => {}
        }
        let fresh2 = (*dest).offset;
        (*dest).offset = ((*dest).offset).wrapping_add(1);
        *((*dest).str_0).offset(fresh2 as isize) = *src;
        unescaped = true;
        src = src.offset(1);
        src;
    }
}
