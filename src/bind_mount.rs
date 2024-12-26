use crate::*;
use crate::{types::*, utils::xcalloc};
use ::libc;
use libc::strchr;

static mut FLAG_DATA: [MountOptionHumanReadable; 9] = [
    MountOptionHumanReadable {
        flag: 0,
        name: b"rw\0" as *const u8 as *const libc::c_char,
    },
    MountOptionHumanReadable {
        flag: MS_RDONLY as _,
        name: b"ro\0" as *const u8 as *const libc::c_char,
    },
    MountOptionHumanReadable {
        flag: MS_NOSUID as _,
        name: b"nosuid\0" as *const u8 as *const libc::c_char,
    },
    MountOptionHumanReadable {
        flag: MS_NODEV as _,
        name: b"nodev\0" as *const u8 as *const libc::c_char,
    },
    MountOptionHumanReadable {
        flag: MS_NOEXEC as _,
        name: b"noexec\0" as *const u8 as *const libc::c_char,
    },
    MountOptionHumanReadable {
        flag: MS_NOATIME as _,
        name: b"noatime\0" as *const u8 as *const libc::c_char,
    },
    MountOptionHumanReadable {
        flag: MS_NODIRATIME as _,
        name: b"nodiratime\0" as *const u8 as *const libc::c_char,
    },
    MountOptionHumanReadable {
        flag: MS_RELATIME as _,
        name: b"relatime\0" as *const u8 as *const libc::c_char,
    },
    MountOptionHumanReadable {
        flag: 0,
        name: std::ptr::null_mut(),
    },
];

unsafe fn skip_token(mut line: *mut libc::c_char, mut eat_whitespace: bool) -> *mut libc::c_char {
    let mut line: *mut u8 = line.cast();
    while *line != b' ' && *line != b'\n' {
        line = line.add(1);
    }
    if eat_whitespace && *line == b' ' {
        line = line.add(1);
    }
    return line.cast();
}

unsafe fn unescape_inline(mut escaped: *mut libc::c_char) -> *mut libc::c_char {
    let mut unescaped = std::ptr::null_mut();
    let mut res: *mut u8 = std::ptr::null_mut();
    let mut end: *const u8 = std::ptr::null();
    let mut escaped: *mut u8 = escaped.cast();
    res = escaped;
    end = escaped.add(strlen(escaped as _));
    unescaped = escaped;
    while escaped < end as _ {
        if *escaped == b'\\' {
            let octal_repr = unescaped;
            unescaped = unescaped.add(1);
            *octal_repr = (*escaped.add(1) - b'0') << 6
                | (*escaped.add(2) - b'0') << 3
                | (*escaped.add(3) - b'0') << 0;
            escaped = escaped.add(4);
        } else {
            let fresh1 = escaped;
            escaped = escaped.add(1);
            let fresh2 = unescaped;
            unescaped = unescaped.add(1);
            *fresh2 = *fresh1;
        }
    }
    *unescaped = 0;
    return res.cast();
}

unsafe fn match_token(
    mut token: *const libc::c_char,
    mut token_end: *const libc::c_char,
    mut str: *const libc::c_char,
) -> bool {
    while token != token_end && *token == *str {
        token = token.add(1);
        str = str.add(1);
    }
    if token == token_end {
        return *str == 0;
    }
    return false;
}

unsafe fn decode_mountoptions(mut options: *const libc::c_char) -> libc::c_ulong {
    let mut token = std::ptr::null();
    let mut end_token = std::ptr::null();
    let mut i: usize = 0;
    let mut flags: u64 = 0;
    token = options;
    loop {
        end_token = strchr(token, ',' as i32);
        if end_token.is_null() {
            end_token = token.add(strlen(token));
        }
        i = 0;
        while !FLAG_DATA[i].name.is_null() {
            if match_token(token, end_token, FLAG_DATA[i].name) {
                flags |= FLAG_DATA[i].flag as u64;
                break;
            } else {
                i += 1;
            }
        }
        if *end_token != 0 {
            token = end_token.offset(1);
        } else {
            token = std::ptr::null_mut();
        }
        if token.is_null() {
            break;
        }
    }
    return flags;
}

unsafe fn count_lines(mut data: *const libc::c_char) -> libc::c_uint {
    let mut count: libc::c_uint = 0;
    let mut p: *const u8 = data.cast();
    while *p as libc::c_int != 0 {
        if *p == b'\n' {
            count += 1;
        }
        p = p.add(1);
    }
    if p > data as _ && *p.sub(1) != b'\n' {
        count += 1;
    }
    return count;
}

fn count_mounts(mut line: &mut MountInfoLine) -> libc::c_int {
    let mut res = if !line.covered { 1 } else { 0 };
    if line.first_child.is_null() {
        return res;
    }
    // Safety: We do check before hand if the pointer is null
    let mut child = unsafe { &mut *line.first_child };
    loop {
        res += count_mounts(child);
        if (*child).next_sibling.is_null() {
            break;
        }

        // Safety: We do check before hand if the pointer is null
        child = unsafe { &mut *child.next_sibling };
    }
    return res;
}

unsafe fn collect_mounts(mut info: *mut MountInfo, mut line: *mut MountInfoLine) -> *mut MountInfo {
    let mut child = std::ptr::null_mut();
    if !(*line).covered {
        (*info).mountpoint = xstrdup((*line).mountpoint);
        (*info).options = decode_mountoptions((*line).options);
        info = info.offset(1);
    }
    child = (*line).first_child;
    while !child.is_null() {
        info = collect_mounts(info, child);
        child = (*child).next_sibling;
    }
    return info;
}

unsafe fn parse_mountinfo(
    mut proc_fd: libc::c_int,
    mut root_mount: *const libc::c_char,
) -> MountTab {
    let mut mountinfo = std::ptr::null_mut() as *mut libc::c_char;
    let mut lines = std::ptr::null_mut() as *mut MountInfoLine;
    let mut by_id = std::ptr::null_mut() as *mut *mut MountInfoLine;
    let mut mount_tab = std::ptr::null_mut() as MountTab;
    let mut end_tab = std::ptr::null_mut();
    let mut n_mounts: libc::c_int = 0;
    let mut line = std::ptr::null_mut();
    let mut i: libc::c_uint = 0;
    let mut max_id: libc::c_int = 0;
    let mut n_lines: libc::c_uint = 0;
    let mut root: libc::c_int = 0;
    mountinfo = load_file_at(
        proc_fd,
        b"self/mountinfo\0" as *const u8 as *const libc::c_char,
    );
    if mountinfo.is_null() {
        die_with_error!(b"Can't open /proc/self/mountinfo\0" as *const u8 as *const libc::c_char);
    }
    n_lines = count_lines(mountinfo);
    lines =
        xcalloc(n_lines as size_t, ::core::mem::size_of::<MountInfoLine>()) as *mut MountInfoLine;
    max_id = 0;
    line = mountinfo;
    i = 0;
    root = -1;
    while *line as libc::c_int != 0 {
        let mut rc: libc::c_int = 0;
        let mut consumed = 0;
        let mut maj: libc::c_uint = 0;
        let mut min: libc::c_uint = 0;
        let mut end = 0 as *mut libc::c_char;
        let mut rest = 0 as *mut libc::c_char;
        let mut mountpoint = 0 as *mut libc::c_char;
        let mut mountpoint_end = 0 as *mut libc::c_char;
        let mut options = 0 as *mut libc::c_char;
        let mut options_end = 0 as *mut libc::c_char;
        let mut next_line = 0 as *mut libc::c_char;
        assert!(i < n_lines);
        end = strchr(line, '\n' as i32);
        if !end.is_null() {
            *end = 0;
            next_line = end.offset(1);
        } else {
            next_line = line.add(strlen(line));
        }
        rc = sscanf(
            line,
            c"%d %d %u:%u %n".as_ptr(),
            &mut (*lines.add(i as _)).id as *mut libc::c_int,
            &mut (*lines.add(i as _)).parent_id as *mut libc::c_int,
            &mut maj as *mut libc::c_uint,
            &mut min as *mut libc::c_uint,
            &mut consumed as *mut libc::c_int,
        );
        if rc != 4 {
            die!(b"Can't parse mountinfo line\0" as *const u8 as *const libc::c_char);
        }
        rest = line.offset(consumed as isize);
        rest = skip_token(rest, true);
        mountpoint = rest;
        rest = skip_token(rest, false);
        let fresh3 = rest;
        rest = rest.offset(1);
        mountpoint_end = fresh3;
        options = rest;
        rest = skip_token(rest, false);
        options_end = rest;
        *mountpoint_end = 0;
        let ref mut fresh4 = (*lines.offset(i as isize)).mountpoint;
        *fresh4 = unescape_inline(mountpoint);
        *options_end = 0;
        let ref mut fresh5 = (*lines.offset(i as isize)).options;
        *fresh5 = options;
        if (*lines.offset(i as isize)).id > max_id {
            max_id = (*lines.offset(i as isize)).id;
        }
        if (*lines.offset(i as isize)).parent_id > max_id {
            max_id = (*lines.offset(i as isize)).parent_id;
        }
        if path_equal((*lines.offset(i as isize)).mountpoint, root_mount) {
            root = i as libc::c_int;
        }
        i = i.wrapping_add(1);
        line = next_line;
    }
    assert!(i == n_lines);
    if root == -1 {
        mount_tab = xcalloc(1, ::core::mem::size_of::<MountInfo>()) as MountTab;
        return (if 0 != 0 {
            mount_tab as *mut libc::c_void
        } else {
            steal_pointer(&mut mount_tab as *mut MountTab as *mut libc::c_void)
        }) as MountTab;
    }
    by_id = xcalloc(
        (max_id + 1) as size_t,
        ::core::mem::size_of::<*mut MountInfoLine>(),
    ) as *mut *mut MountInfoLine;
    i = 0;
    while i < n_lines {
        let ref mut fresh6 = *by_id.offset((*lines.offset(i as isize)).id as isize);
        *fresh6 = &mut *lines.offset(i as isize) as *mut MountInfoLine;
        i = i.wrapping_add(1);
    }
    i = 0;
    while i < n_lines {
        let mut this: *mut MountInfoLine = &mut *lines.offset(i as isize) as *mut MountInfoLine;
        let mut parent = *by_id.offset((*this).parent_id as isize);
        let mut to_sibling = 0 as *mut *mut MountInfoLine;
        let mut sibling = 0 as *mut MountInfoLine;
        let mut covered = false;
        if has_path_prefix((*this).mountpoint, root_mount) && !parent.is_null() {
            if strcmp((*parent).mountpoint, (*this).mountpoint) == 0 {
                (*parent).covered = true;
            }
            to_sibling = &mut (*parent).first_child;
            sibling = (*parent).first_child;
            while !sibling.is_null() {
                if has_path_prefix((*this).mountpoint, (*sibling).mountpoint) {
                    covered = true;
                    break;
                } else {
                    if has_path_prefix((*sibling).mountpoint, (*this).mountpoint) {
                        *to_sibling = (*sibling).next_sibling;
                    } else {
                        to_sibling = &mut (*sibling).next_sibling;
                    }
                    sibling = (*sibling).next_sibling;
                }
            }
            if !covered {
                *to_sibling = this;
            }
        }
        i = i.wrapping_add(1);
    }
    n_mounts = count_mounts(&mut *lines.offset(root as isize));
    mount_tab = xcalloc(
        (n_mounts + 1) as size_t,
        ::core::mem::size_of::<MountInfo>(),
    ) as MountTab;
    end_tab = collect_mounts(&mut *mount_tab.offset(0), &mut *lines.offset(root as isize));
    assert!(end_tab == &mut *mount_tab.offset(n_mounts as isize) as *mut MountInfo);
    return (if 0 != 0 {
        mount_tab as *mut libc::c_void
    } else {
        steal_pointer(&mut mount_tab as *mut MountTab as *mut libc::c_void)
    }) as MountTab;
}

pub unsafe fn bind_mount(
    mut proc_fd: libc::c_int,
    mut src: *const libc::c_char,
    mut dest: *const libc::c_char,
    mut options: bind_option_t,
    mut failing_path: *mut *mut libc::c_char,
) -> bind_mount_result {
    let mut readonly = options as libc::c_uint & BIND_READONLY as libc::c_int as libc::c_uint != 0;
    let mut devices = options as libc::c_uint & BIND_DEVICES as libc::c_int as libc::c_uint != 0;
    let mut recursive =
        options as libc::c_uint & BIND_RECURSIVE as libc::c_int as libc::c_uint != 0;
    let mut current_flags: libc::c_ulong = 0;
    let mut new_flags: libc::c_ulong = 0;
    let mut mount_tab = std::ptr::null_mut() as MountTab;
    let mut resolved_dest = std::ptr::null_mut() as *mut libc::c_char;
    let mut dest_proc = std::ptr::null_mut() as *mut libc::c_char;
    let mut oldroot_dest_proc = std::ptr::null_mut() as *mut libc::c_char;
    let mut kernel_case_combination = std::ptr::null_mut() as *mut libc::c_char;
    let mut dest_fd = -1;
    let mut i: libc::c_int = 0;
    if !src.is_null()
        && mount(
            src,
            dest,
            std::ptr::null_mut() as *const libc::c_char,
            (MS_SILENT
                | MS_BIND
                | (if recursive as libc::c_int != 0 {
                    MS_REC
                } else {
                    0
                })) as libc::c_ulong,
            std::ptr::null_mut() as *const libc::c_void,
        ) != 0
    {
        return BIND_MOUNT_ERROR_MOUNT;
    }
    resolved_dest = realpath(dest, std::ptr::null_mut() as *mut libc::c_char);
    if resolved_dest.is_null() {
        return BIND_MOUNT_ERROR_REALPATH_DEST;
    }
    dest_fd = ({
        let mut __result: libc::c_long = 0;
        loop {
            __result = open(resolved_dest, 0o10000000 | 0o2000000) as libc::c_long;
            if !(__result == -1 && errno!() == EINTR) {
                break;
            }
        }
        __result
    }) as libc::c_int;
    if dest_fd < 0 {
        if !failing_path.is_null() {
            *failing_path = (if 0 != 0 {
                resolved_dest as *mut libc::c_void
            } else {
                steal_pointer(&mut resolved_dest as *mut *mut libc::c_char as *mut libc::c_void)
            }) as *mut libc::c_char;
        }
        return BIND_MOUNT_ERROR_REOPEN_DEST;
    }
    dest_proc = xasprintf(
        b"/proc/self/fd/%d\0" as *const u8 as *const libc::c_char,
        dest_fd,
    );
    oldroot_dest_proc = get_oldroot_path(dest_proc);
    kernel_case_combination = readlink_malloc(oldroot_dest_proc);
    if kernel_case_combination.is_null() {
        if !failing_path.is_null() {
            *failing_path = (if 0 != 0 {
                resolved_dest as *mut libc::c_void
            } else {
                steal_pointer(&mut resolved_dest as *mut *mut libc::c_char as *mut libc::c_void)
            }) as *mut libc::c_char;
        }
        return BIND_MOUNT_ERROR_READLINK_DEST_PROC_FD;
    }
    mount_tab = parse_mountinfo(proc_fd, kernel_case_combination);
    if ((*mount_tab.offset(0)).mountpoint).is_null() {
        if !failing_path.is_null() {
            *failing_path = (if 0 != 0 {
                kernel_case_combination as *mut libc::c_void
            } else {
                steal_pointer(
                    &mut kernel_case_combination as *mut *mut libc::c_char as *mut libc::c_void,
                )
            }) as *mut libc::c_char;
        }
        errno!() = EINVAL;
        return BIND_MOUNT_ERROR_FIND_DEST_MOUNT;
    }
    assert!(path_equal(
        (*mount_tab.offset(0)).mountpoint,
        kernel_case_combination,
    ));
    current_flags = (*mount_tab.offset(0)).options;
    new_flags = current_flags
        | (if devices as libc::c_int != 0 {
            0
        } else {
            MS_NODEV as _
        }) as libc::c_ulong
        | MS_NOSUID as libc::c_ulong
        | (if readonly as libc::c_int != 0 {
            MS_RDONLY as _
        } else {
            0
        }) as libc::c_ulong;
    if new_flags != current_flags
        && mount(
            b"none\0" as *const u8 as *const libc::c_char,
            resolved_dest,
            std::ptr::null_mut() as *const libc::c_char,
            (MS_SILENT | MS_BIND | MS_REMOUNT) as libc::c_ulong | new_flags,
            std::ptr::null_mut() as *const libc::c_void,
        ) != 0
    {
        if !failing_path.is_null() {
            *failing_path = (if 0 != 0 {
                resolved_dest as *mut libc::c_void
            } else {
                steal_pointer(&mut resolved_dest as *mut *mut libc::c_char as *mut libc::c_void)
            }) as *mut libc::c_char;
        }
        return BIND_MOUNT_ERROR_REMOUNT_DEST;
    }
    if recursive {
        i = 1;
        while !((*mount_tab.offset(i as isize)).mountpoint).is_null() {
            current_flags = (*mount_tab.offset(i as isize)).options;
            new_flags = current_flags
                | (if devices as libc::c_int != 0 {
                    0
                } else {
                    MS_NODEV as _
                }) as libc::c_ulong
                | MS_NOSUID as libc::c_ulong
                | (if readonly as libc::c_int != 0 {
                    MS_RDONLY as _
                } else {
                    0
                }) as libc::c_ulong;
            if new_flags != current_flags
                && mount(
                    b"none\0" as *const u8 as *const libc::c_char,
                    (*mount_tab.offset(i as isize)).mountpoint,
                    std::ptr::null_mut() as *const libc::c_char,
                    (MS_SILENT | MS_BIND | MS_REMOUNT) as libc::c_ulong | new_flags,
                    std::ptr::null_mut() as *const libc::c_void,
                ) != 0
                && errno!() != EACCES
            {
                if !failing_path.is_null() {
                    *failing_path = xstrdup((*mount_tab.offset(i as isize)).mountpoint);
                }
                return BIND_MOUNT_ERROR_REMOUNT_SUBMOUNT;
            }
            i += 1;
        }
    }
    return BIND_MOUNT_SUCCESS;
}

unsafe fn bind_mount_result_to_string(
    mut res: bind_mount_result,
    mut failing_path: *const libc::c_char,
    mut want_errno_p: *mut bool,
) -> *mut libc::c_char {
    let mut string = std::ptr::null_mut() as *mut libc::c_char;
    let mut want_errno = true;
    match res as libc::c_uint {
        1 => {
            string = xstrdup(
                b"Unable to mount source on destination\0" as *const u8 as *const libc::c_char,
            );
        }
        2 => {
            string = xstrdup(b"realpath(destination)\0" as *const u8 as *const libc::c_char);
        }
        3 => {
            string = xasprintf(
                b"open(\"%s\", O_PATH)\0" as *const u8 as *const libc::c_char,
                failing_path,
            );
        }
        4 => {
            string = xasprintf(
                b"readlink(/proc/self/fd/N) for \"%s\"\0" as *const u8 as *const libc::c_char,
                failing_path,
            );
        }
        5 => {
            string = xasprintf(
                b"Unable to find \"%s\" in mount table\0" as *const u8 as *const libc::c_char,
                failing_path,
            );
            want_errno = false;
        }
        6 => {
            string = xasprintf(
                b"Unable to remount destination \"%s\" with correct flags\0" as *const u8
                    as *const libc::c_char,
                failing_path,
            );
        }
        7 => {
            string = xasprintf(
                b"Unable to apply mount flags: remount \"%s\"\0" as *const u8
                    as *const libc::c_char,
                failing_path,
            );
        }
        0 => {
            string = xstrdup(b"Success\0" as *const u8 as *const libc::c_char);
        }
        _ => {
            string = xstrdup(
                b"(unknown/invalid bind_mount_result)\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if !want_errno_p.is_null() {
        *want_errno_p = want_errno;
    }
    return string;
}
