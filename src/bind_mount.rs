use std::ffi::{CStr, CString, OsStr, OsString};
use std::ops::Not;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::str::FromStr;

use nix::fcntl::OFlag;
use nix::mount::MsFlags;
use nix::sys::stat::Mode;

use crate::{nix_retry, types::*};

pub fn bind_mount(
    proc_fd: RawFd,
    src: Option<&CStr>,
    dest: &CStr,
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

    if let Some(src) = src {
        if nix::mount::mount(
            Some(src),
            dest,
            Option::<&CStr>::None,
            MsFlags::MS_SILENT
                | MsFlags::MS_BIND
                | recursive
                    .then_some(MsFlags::MS_REC)
                    .unwrap_or_else(MsFlags::empty),
            Option::<&CStr>::None,
        )
        .is_err()
        {
            return BIND_MOUNT_ERROR_MOUNT;
        }
    }

    //unsafe { realpath(dest, std::ptr::null_mut()) };
    let resolved_dest = unsafe { libc::realpath(dest.as_ptr(), std::ptr::null_mut()) };
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
    let dest_proc = std::path::PathBuf::from(format!("/proc/self/fd/{dest_fd}"));
    let oldroot_dest_proc = {
        let mut out = OsString::from("/oldroot");
        out.push(dest_proc.as_os_str());
        std::path::PathBuf::from(out)
    };
    //unsafe { get_oldroot_path(dest_proc.as_ptr()) };
    let kernel_case_combination = nix::fcntl::readlink(&oldroot_dest_proc).map(PathBuf::from);
    if kernel_case_combination.is_err() {
        return BIND_MOUNT_ERROR_READLINK_DEST_PROC_FD;
    }
    let kernel_case_combination = kernel_case_combination.unwrap();

    let mount_tab = crate::parse_mountinfo::parse_mountinfo(proc_fd, &kernel_case_combination);

    assert!(!mount_tab.is_empty());
    assert!(mount_tab[0].mountpoint.as_os_str() == kernel_case_combination);

    let mut current_flags = mount_tab[0].options;
    let mut new_flags = current_flags
        | MsFlags::MS_NOSUID
        | devices
            .not()
            .then_some(MsFlags::MS_NODEV)
            .unwrap_or_else(MsFlags::empty)
        | readonly
            .then_some(MsFlags::MS_RDONLY)
            .unwrap_or_else(MsFlags::empty);
    if new_flags != current_flags {
        if nix::mount::mount(
            Some("none"),
            resolved_dest,
            Option::<&CStr>::None,
            MsFlags::MS_SILENT | MsFlags::MS_BIND | MsFlags::MS_REMOUNT | new_flags,
            Option::<&CStr>::None,
        )
        .is_err()
        {
            return BIND_MOUNT_ERROR_REMOUNT_DEST;
        }
    }
    if recursive {
        for elem in mount_tab.iter().skip(1) {
            current_flags = elem.options;
            new_flags = current_flags
                | MsFlags::MS_NOSUID
                | devices
                    .not()
                    .then_some(MsFlags::MS_NODEV)
                    .unwrap_or_else(MsFlags::empty)
                | readonly
                    .then_some(MsFlags::MS_RDONLY)
                    .unwrap_or_else(MsFlags::empty);
            if new_flags != current_flags {
                let res = nix::mount::mount(
                    Some("none"),
                    &elem.mountpoint,
                    Option::<&CStr>::None,
                    MsFlags::MS_SILENT | MsFlags::MS_BIND | MsFlags::MS_REMOUNT | new_flags,
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
