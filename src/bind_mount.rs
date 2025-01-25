use std::ffi::{CStr, CString, OsString};
use std::ops::Not;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

use nix::fcntl::OFlag;
use nix::mount::MsFlags;
use nix::sys::stat::Mode;
use nix::NixPath;

use crate::nix_retry;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Hash, serde::Serialize, serde::Deserialize)]
    pub struct BindOptions : u32 {
        const BIND_DEVICES  = 0b000000000001;
        const BIND_READONLY  = 0b000000000010;
        const BIND_RECURSIVE  = 0b000000000100;
    }
}

/// Will return an error on invalid Paths.
/// Will return Ok(None) in case of [`libc::realpath`] returing nullptr
/// Otherwise in case of success it will return the value as a CString. This will make another
/// allocation since we can't make sure that the global_allocator is using the same as libc's
/// allocator. Meaning we have to allocate and copy the result
fn realpath_wrapper<P: nix::NixPath + ?Sized>(
    path: &P,
) -> Result<Option<CString>, nix::errno::Errno> {
    // SAFETY: This is safe because with NixPath we can't get a nullptr. It is also a path-like
    // object
    path.with_nix_path(|p| unsafe { libc::realpath(p.as_ptr(), std::ptr::null_mut()) })
        .map(|ptr| {
            if ptr.is_null() {
                None
            } else {
                // SAFETY: this is safe because ptr is not null and points to something that was
                // malloc'ed by the libc
                let cstring = CString::from(unsafe { CStr::from_ptr(ptr) });
                // SAFETY: We can safely free this one since the `cstring` is a new allocation that
                // has cloned data
                unsafe { libc::free(ptr.cast()) };
                Some(cstring)
            }
        })
}

#[derive(Clone, Debug, Hash, serde::Serialize, serde::Deserialize)]
pub enum BindMountError {
    Mount,
    RealpathDest,
    ReopenDest(OsString),
    ReadlinkDestProcFd(OsString),
    FindDestMount(OsString),
    RemountDest(OsString),
    RemountSubmount(OsString),
}

pub fn bind_mount<'a, 'b, P1: ?Sized + NixPath, P2: ?Sized + NixPath>(
    proc_fd: BorrowedFd<'_>,
    src: Option<&'a P1>,
    dest: &'b P2,
    options: BindOptions,
) -> Result<(), BindMountError> {
    let readonly = options.contains(BindOptions::BIND_READONLY);
    let devices = options.contains(BindOptions::BIND_DEVICES);
    let recursive = options.contains(BindOptions::BIND_RECURSIVE);

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
            return Err(BindMountError::Mount);
        }
    }

    let resolved_dest = realpath_wrapper(dest);
    if matches!(resolved_dest, Err(_) | Ok(None)) {
        return Err(BindMountError::RealpathDest);
    }

    let resolved_dest = resolved_dest.unwrap().unwrap();
    let dest_fd = nix_retry!(nix::fcntl::open(
        resolved_dest.as_c_str(),
        OFlag::O_PATH | OFlag::O_CLOEXEC,
        Mode::empty(),
    ));
    if dest_fd.is_err() {
        return Err(BindMountError::ReopenDest(OsString::from_vec(
            resolved_dest.into_bytes(),
        )));
    }
    let dest_fd = dest_fd.unwrap();

    let dest_proc = std::path::PathBuf::from(format!("/proc/self/fd/{dest_fd}"));
    let oldroot_dest_proc = {
        let mut out = OsString::from("/oldroot/");
        out.push(dest_proc.as_os_str());
        std::path::PathBuf::from(out)
    };
    let kernel_case_combination = nix::fcntl::readlink(&oldroot_dest_proc).map(PathBuf::from);
    if kernel_case_combination.is_err() {
        return Err(BindMountError::ReadlinkDestProcFd(OsString::from_vec(
            resolved_dest.into_bytes(),
        )));
    }
    let kernel_case_combination = kernel_case_combination.unwrap();

    let mount_tab = crate::parse_mountinfo::parse_mountinfo(proc_fd, &kernel_case_combination);

    if mount_tab.is_empty() || mount_tab[0].mountpoint.as_os_str() != kernel_case_combination {
        return Err(BindMountError::FindDestMount(
            kernel_case_combination.into_os_string(),
        ));
    }

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
            resolved_dest.as_c_str(),
            Option::<&CStr>::None,
            MsFlags::MS_SILENT | MsFlags::MS_BIND | MsFlags::MS_REMOUNT | new_flags,
            Option::<&CStr>::None,
        )
        .is_err()
        {
            return Err(BindMountError::ReadlinkDestProcFd(OsString::from_vec(
                resolved_dest.into_bytes(),
            )));
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
                    return Err(BindMountError::ReadlinkDestProcFd(
                        elem.mountpoint.clone().into_os_string(),
                    ));
                }
            }
        }
    }

    Ok(())
}
