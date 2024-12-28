use std::collections::HashMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::BufReader;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt as _};
use std::path::{Path, PathBuf};

use bstr::ByteSlice;
use bstr::{io::BufReadExt, BStr, BString};
use nix::fcntl::OFlag;
use nix::mount::MsFlags;
use nix::sys::stat::Mode;

use crate::{nix_retry, retry, types::*};

pub fn bind_mount(
    proc_fd: libc::c_int,
    src: *const libc::c_char,
    dest: *const libc::c_char,
    options: bind_option_t,
    _failing_path: *mut *mut libc::c_char,
) -> bind_mount_result {
    if !_failing_path.is_null() {
        unsafe {
            _failing_path.write(std::ptr::null_mut());
        }
    }
    let readonly = options & BIND_READONLY != 0;
    let devices = options & BIND_DEVICES != 0;
    let recursive = options & BIND_RECURSIVE != 0;

    if !src.is_null() {
        let src = unsafe { CStr::from_ptr(src) };
        let dest = unsafe { CStr::from_ptr(dest) };
        if nix::mount::mount(
            Some(src),
            dest,
            Option::<&CStr>::None,
            MsFlags::from_bits_truncate(
                libc::MS_SILENT
                    | libc::MS_BIND
                    | recursive.then_some(libc::MS_REC).unwrap_or_default(),
            ),
            Option::<&CStr>::None,
        )
        .is_err()
        {
            return BIND_MOUNT_ERROR_MOUNT;
        }
    }

    let src = unsafe { CStr::from_ptr(src) };
    let dest = unsafe { CStr::from_ptr(dest) };
    let resolved_dest = unsafe { libc::realpath(dest.as_ptr(), std::ptr::null_mut()) }; //unsafe { realpath(dest, std::ptr::null_mut()) };
    if resolved_dest.is_null() {
        return BIND_MOUNT_ERROR_REALPATH_DEST;
    }
    let resolved_dest = unsafe { CStr::from_ptr(resolved_dest) };
    let dest_fd = nix_retry!(nix::fcntl::open(
        resolved_dest,
        OFlag::O_PATH | OFlag::O_CLOEXEC,
        Mode::empty(),
    )); //retry!(unsafe { open(resolved_dest.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) });
    if dest_fd.is_err() {
        return BIND_MOUNT_ERROR_REOPEN_DEST;
    }
    let dest_fd = dest_fd.unwrap();

    // unsafe { xasprintf(c"/proc/self/fd/%d".as_ptr(), dest_fd) };
    let dest_proc =
        CString::from_vec_with_nul(format!("/proc/self/fd/{dest_fd}\0").into_bytes()).unwrap();
    let oldroot_dest_proc = unsafe { get_oldroot_path(dest_proc.as_ptr()) };
    let kernel_case_combination = unsafe { readlink_malloc(oldroot_dest_proc) };
    if kernel_case_combination.is_null() {
        return BIND_MOUNT_ERROR_READLINK_DEST_PROC_FD;
    }
    let kernel_case_combination_cstr = unsafe { CStr::from_ptr(kernel_case_combination) };

    let mount_tab_box = crate::parse_mountinfo::parse_mountinfo(
        proc_fd,
        OsStr::from_bytes(kernel_case_combination_cstr.to_bytes()),
    );

    let mount_tab = (*mount_tab_box).as_ptr();
    assert!(unsafe {
        (*mount_tab).mountpoint.as_os_str()
            == OsStr::from_bytes(kernel_case_combination_cstr.to_bytes())
    });
    let mut current_flags = mount_tab_box[0].options;
    let mut new_flags = current_flags
        | (if devices { 0 } else { MS_NODEV })
        | MS_NOSUID
        | (if readonly { MS_RDONLY } else { 0 });
    if new_flags != current_flags
        && unsafe {
            mount(
                c"none".as_ptr(),
                resolved_dest.as_ptr(),
                std::ptr::null_mut(),
                MS_SILENT | MS_BIND | MS_REMOUNT | new_flags,
                std::ptr::null_mut(),
            )
        } != 0
    {
        return BIND_MOUNT_ERROR_REMOUNT_DEST;
    }
    if recursive {
        for elem in mount_tab_box.iter().skip(1) {
            current_flags = elem.options;
            new_flags = current_flags
                | if devices { 0 } else { MS_NODEV }
                | MS_NOSUID
                | if readonly { MS_RDONLY } else { 0 };
            if new_flags != current_flags {
                let res = nix::mount::mount(
                    Some(c"none"),
                    &elem.mountpoint,
                    Option::<&CStr>::None,
                    MsFlags::from_bits_truncate(MS_SILENT | MS_BIND | MS_REMOUNT | new_flags),
                    Option::<&CStr>::None,
                );

                if let Err(nix::errno::Errno::EACCES) = res {
                    return BIND_MOUNT_ERROR_REMOUNT_SUBMOUNT;
                }
            }
        }
    }
    return BIND_MOUNT_SUCCESS;
}
