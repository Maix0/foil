use crate::*;
use crate::{types::*, utils::xcalloc};
use ::libc;
use libc::strchr;

static mut FLAG_DATA: [MountOptionHumanReadable; 9] = [
    MountOptionHumanReadable {
        flag: 0,
        name: c"rw".as_ptr(),
    },
    MountOptionHumanReadable {
        flag: MS_RDONLY as _,
        name: c"ro".as_ptr(),
    },
    MountOptionHumanReadable {
        flag: MS_NOSUID as _,
        name: c"nosuid".as_ptr(),
    },
    MountOptionHumanReadable {
        flag: MS_NODEV as _,
        name: c"nodev".as_ptr(),
    },
    MountOptionHumanReadable {
        flag: MS_NOEXEC as _,
        name: c"noexec".as_ptr(),
    },
    MountOptionHumanReadable {
        flag: MS_NOATIME as _,
        name: c"noatime".as_ptr(),
    },
    MountOptionHumanReadable {
        flag: MS_NODIRATIME as _,
        name: c"nodiratime".as_ptr(),
    },
    MountOptionHumanReadable {
        flag: MS_RELATIME as _,
        name: c"relatime".as_ptr(),
    },
    MountOptionHumanReadable {
        flag: 0,
        name: std::ptr::null_mut(),
    },
];

unsafe fn skip_token(line: *mut libc::c_char, eat_whitespace: bool) -> *mut libc::c_char {
    let mut line: *mut u8 = line.cast();
    while *line != b' ' && *line != b'\n' {
        line = line.add(1);
    }
    if eat_whitespace && *line == b' ' {
        line = line.add(1);
    }
    return line.cast();
}

unsafe fn unescape_inline(escaped: *mut libc::c_char) -> *mut libc::c_char {
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
            // == escaped++
            let esc_min1 = escaped;
            escaped = escaped.add(1);

            //  == unescaped++
            let unesc_min1 = unescaped;
            unescaped = unescaped.add(1);

            *unesc_min1 = *esc_min1;
        }
    }
    *unescaped = 0;
    return res.cast();
}

unsafe fn match_token(
    mut token: *const libc::c_char,
    token_end: *const libc::c_char,
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

unsafe fn decode_mountoptions(options: *const libc::c_char) -> libc::c_ulong {
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
        token = if *end_token != 0 {
            end_token.offset(1)
        } else {
            std::ptr::null_mut()
        };

        if token.is_null() {
            break;
        }
    }
    return flags;
}

unsafe fn count_lines(data: *const libc::c_char) -> libc::c_uint {
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

fn count_mounts(line: &mut MountInfoLine) -> libc::c_int {
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

unsafe fn collect_mounts(mut info: *mut MountInfo, line: *mut MountInfoLine) -> *mut MountInfo {
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

unsafe fn parse_mountinfo(proc_fd: libc::c_int, root_mount: *const libc::c_char) -> MountTab {
    let mut by_id = std::ptr::null_mut() as *mut *mut MountInfoLine;
    let mut mount_tab = std::ptr::null_mut() as MountTab;
    let mut end_tab = std::ptr::null_mut();
    let mut n_mounts: libc::c_int = 0;

    let mountinfo = load_file_at(proc_fd, c"self/mountinfo".as_ptr());
    if mountinfo.is_null() {
        die_with_error!(c"Can't open /proc/self/mountinfo".as_ptr());
    }

    let n_lines = count_lines(mountinfo) as usize;
    let lines =
        xcalloc(n_lines as size_t, ::core::mem::size_of::<MountInfoLine>()) as *mut MountInfoLine;
    let mut max_id = 0;
    let mut line = mountinfo;
    let mut i = 0usize;
    let mut root = -1;
    while *line != 0 {
        let mut consumed = 0;
        let mut maj: libc::c_uint = 0;
        let mut min: libc::c_uint = 0;

        assert!(i < n_lines);
        let end = strchr(line, '\n' as i32);

        let next_line = if !end.is_null() {
            *end = 0;
            end.offset(1)
        } else {
            line.add(strlen(line))
        };
        let rc = sscanf(
            line,
            c"%d %d %u:%u %n".as_ptr(),
            &mut (*lines.add(i)).id as *mut libc::c_int,
            &mut (*lines.add(i)).parent_id as *mut libc::c_int,
            &mut maj as *mut libc::c_uint,
            &mut min as *mut libc::c_uint,
            &mut consumed as *mut libc::c_int,
        );
        if rc != 4 {
            die!(c"Can't parse mountinfo line".as_ptr());
        }
        let mut rest = line.offset(consumed as isize);
        rest = skip_token(rest, true);

        let mountpoint = rest;
        rest = skip_token(rest, false);

        let fresh3 = rest;
        rest = rest.offset(1);
        let mountpoint_end = fresh3;
        let options = rest;
        rest = skip_token(rest, false);
        let options_end = rest;
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
        i += 1;
        line = next_line;
    }
    assert!(i == n_lines);

    if root == -1 {
        mount_tab = xcalloc(1, ::core::mem::size_of::<MountInfo>()) as MountTab;
        return mount_tab as MountTab;
    }

    by_id = xcalloc(
        (max_id + 1) as size_t,
        ::core::mem::size_of::<*mut MountInfoLine>(),
    ) as *mut *mut MountInfoLine;

    i = 0;
    while i < n_lines {
        *(by_id.add((*lines.add(i)).id as _)) = &mut *lines.add(i) as *mut MountInfoLine;
        i += 1;
    }
    i = 0;
    while i < n_lines {
        let this: *mut MountInfoLine = &mut *lines.add(i) as *mut MountInfoLine;
        let parent = *by_id.add((*this).parent_id as usize);
        let mut to_sibling = std::ptr::null_mut();
        let mut sibling = std::ptr::null_mut();
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
        i = 1;
    }
    n_mounts = count_mounts(&mut *lines.offset(root as _));
    mount_tab = xcalloc((n_mounts + 1) as _, ::core::mem::size_of::<MountInfo>()) as MountTab;
    end_tab = collect_mounts(mount_tab, lines.add(root as _));

    assert!(end_tab == &mut *mount_tab.add(n_mounts as _));
    return mount_tab as MountTab;
}

pub unsafe fn bind_mount(
    proc_fd: libc::c_int,
    src: *const libc::c_char,
    dest: *const libc::c_char,
    options: bind_option_t,
    failing_path: *mut *mut libc::c_char,
) -> bind_mount_result {
    let readonly = options & BIND_READONLY != 0;
    let devices = options & BIND_DEVICES != 0;
    let recursive = options & BIND_RECURSIVE != 0;

    if !src.is_null()
        && mount(
            src,
            dest,
            std::ptr::null_mut(),
            MS_SILENT | MS_BIND | if recursive { MS_REC } else { 0 },
            std::ptr::null_mut(),
        ) != 0
    {
        return BIND_MOUNT_ERROR_MOUNT;
    }
    let resolved_dest = realpath(dest, std::ptr::null_mut());
    if resolved_dest.is_null() {
        return BIND_MOUNT_ERROR_REALPATH_DEST;
    }
    let dest_fd = retry!(open(resolved_dest, 0o10000000 | 0o2000000));
    if dest_fd < 0 {
        if !failing_path.is_null() {
            *failing_path = resolved_dest;
        }
        return BIND_MOUNT_ERROR_REOPEN_DEST;
    }
    let dest_proc = xasprintf(
        c"/proc/self/fd/%d".as_ptr(),
        dest_fd,
    );
    let oldroot_dest_proc = get_oldroot_path(dest_proc);
    let kernel_case_combination = readlink_malloc(oldroot_dest_proc);
    if kernel_case_combination.is_null() {
        if !failing_path.is_null() {
            *failing_path = resolved_dest;
        }
        return BIND_MOUNT_ERROR_READLINK_DEST_PROC_FD;
    }
    let mount_tab = parse_mountinfo(proc_fd, kernel_case_combination);
    if ((*mount_tab).mountpoint).is_null() {
        if !failing_path.is_null() {
            *failing_path = kernel_case_combination;
        }
        errno!() = EINVAL;
        return BIND_MOUNT_ERROR_FIND_DEST_MOUNT;
    }
    assert!(path_equal((*mount_tab).mountpoint, kernel_case_combination,));
    let mut current_flags = (*mount_tab).options;
    let mut new_flags = current_flags
        | (if devices { 0 } else { MS_NODEV })
        | MS_NOSUID
        | (if readonly { MS_RDONLY } else { 0 });
    if new_flags != current_flags
        && mount(
            c"none".as_ptr(),
            resolved_dest,
            std::ptr::null_mut(),
            MS_SILENT | MS_BIND | MS_REMOUNT | new_flags,
            std::ptr::null_mut(),
        ) != 0
    {
        if !failing_path.is_null() {
            *failing_path = resolved_dest;
        }
        return BIND_MOUNT_ERROR_REMOUNT_DEST;
    }
    if recursive {
        let mut i = 1;
        while !((*mount_tab.add(i)).mountpoint).is_null() {
            current_flags = (*mount_tab.add(i)).options;
            new_flags = current_flags
                | if devices { 0 } else { MS_NODEV }
                | MS_NOSUID
                | if readonly { MS_RDONLY } else { 0 };
            if new_flags != current_flags
                && mount(
                    c"none".as_ptr(),
                    (*mount_tab.add(i)).mountpoint,
                    std::ptr::null_mut(),
                    MS_SILENT | MS_BIND | MS_REMOUNT | new_flags,
                    std::ptr::null_mut(),
                ) != 0
                && errno!() != EACCES
            {
                if !failing_path.is_null() {
                    *failing_path = xstrdup((*mount_tab.add(i)).mountpoint);
                }
                return BIND_MOUNT_ERROR_REMOUNT_SUBMOUNT;
            }
            i += 1;
        }
    }
    return BIND_MOUNT_SUCCESS;
}
