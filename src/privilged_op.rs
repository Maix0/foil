use std::{ffi::OsString, num::NonZeroUsize, os::fd::RawFd};

use nix::mount::MsFlags;

use crate::{
    bind_mount::{bind_mount, BindMountError, BindOptions},
    types::{opt_unshare_uts, proc_fd},
};

pub enum PrivilegedOpError {
    ReadOnlyRemount {
        path: std::path::PathBuf,
        err: BindMountError,
    },
    BindMount {
        dest: std::path::PathBuf,
        src: std::path::PathBuf,
        err: BindMountError,
    },
    ProcMount {
        path: std::path::PathBuf,
        err: nix::errno::Errno,
    },
    TmpfsTooBig {
        path: std::path::PathBuf,
        requested_size: NonZeroUsize,
    },
    TmpfsMount {
        path: std::path::PathBuf,
        err: nix::errno::Errno,
    },
    DevMount {
        path: std::path::PathBuf,
        err: nix::errno::Errno,
    },
    MqueueMount {
        path: std::path::PathBuf,
        err: nix::errno::Errno,
    },
    OverlayMount {
        path: std::path::PathBuf,
        err: nix::errno::Errno,
        options: OsString,
    },
    HostnameChange {
        requested: OsString,
        err: nix::errno::Errno,
    },
    HostnameNotUnshared,
    UnknownCommand,
}

pub enum PrivilegedOp {
    Done,
    ReadOnlyRemount {
        path: std::path::PathBuf,
    },
    BindMount {
        src: std::path::PathBuf,
        dest: std::path::PathBuf,
        flags: BindOptions,
    },
    ProcMount {
        path: std::path::PathBuf,
    },
    TmpfsMount {
        size: Option<NonZeroUsize>,
        perms: u32,
        path: std::path::PathBuf,
    },
    DevMount {
        path: std::path::PathBuf,
    },
    MqueueMount {
        path: std::path::PathBuf,
    },
    OverlayMount {
        path: std::path::PathBuf,
        options: OsString,
    },
    SetHostname {
        name: OsString,
    },
}

fn send_priviledged_op(op: PrivilegedOp) -> Result<(), PrivilegedOpError> {
    todo!();
}

pub const MAX_TMPFS_BYTES: NonZeroUsize = NonZeroUsize::new(usize::MAX >> 1).unwrap();

pub fn privileged_op(privileged_op_fd: RawFd, op: PrivilegedOp) -> Result<(), PrivilegedOpError> {
    if privileged_op_fd != -1 {
        return send_priviledged_op(op);
    }

    match op {
        PrivilegedOp::Done => Ok(()),

        PrivilegedOp::ReadOnlyRemount { ref path } => bind_mount(
            unsafe { proc_fd },
            Option::<&str>::None,
            path,
            BindOptions::BIND_READONLY,
        )
        .map_err(|err| PrivilegedOpError::ReadOnlyRemount {
            path: path.into(),
            err,
        }),

        PrivilegedOp::BindMount {
            ref src,
            ref dest,
            flags,
        } => bind_mount(
            unsafe { proc_fd },
            Some(src),
            dest,
            BindOptions::BIND_RECURSIVE | flags,
        )
        .map_err(|err| PrivilegedOpError::BindMount {
            src: src.into(),
            dest: dest.into(),
            err,
        }),

        PrivilegedOp::ProcMount { ref path } => nix::mount::mount(
            Some(c"proc"),
            path,
            Some(c"proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            Option::<&str>::None,
        )
        .map_err(|err| PrivilegedOpError::ProcMount {
            path: path.into(),
            err,
        }),

        PrivilegedOp::TmpfsMount {
            size,
            perms,
            ref path,
        } => {
            if size.is_some() && size.unwrap() > MAX_TMPFS_BYTES {
                return Err(PrivilegedOpError::TmpfsTooBig {
                    path: path.into(),
                    requested_size: size.unwrap(),
                });
            }
            let mode = if let Some(size) = size {
                format!("mode={perms:#o},size={size}")
            } else {
                format!("mode={perms:#o}")
            };
            nix::mount::mount(
                Some(c"tmpfs"),
                path,
                Some(c"tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some(mode.as_str()),
            )
            .map_err(|err| PrivilegedOpError::TmpfsMount {
                path: path.into(),
                err,
            })
        }

        PrivilegedOp::DevMount { ref path } => nix::mount::mount(
            Some(c"devpts"),
            path,
            Some(c"devpts"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some(c"newinstance,ptmxmode=0666,mode=620"),
        )
        .map_err(|err| PrivilegedOpError::DevMount {
            path: path.into(),
            err,
        }),

        PrivilegedOp::MqueueMount { ref path } => nix::mount::mount(
            Some(c"mqueue"),
            path,
            Some(c"mqueue"),
            MsFlags::empty(),
            Option::<&str>::None,
        )
        .map_err(|err| PrivilegedOpError::MqueueMount {
            path: path.into(),
            err,
        }),

        PrivilegedOp::OverlayMount {
            ref path,
            ref options,
        } => nix::mount::mount(
            Some(c"overlay"),
            path,
            Some(c"overlay"),
            nix::mount::MsFlags::MS_MGC_VAL,
            Some(options.as_os_str()),
        )
        .map_err(|err| PrivilegedOpError::OverlayMount {
            path: path.into(),
            options: options.into(),
            err,
        }),

        PrivilegedOp::SetHostname { .. } if unsafe { !opt_unshare_uts } => {
            Err(PrivilegedOpError::HostnameNotUnshared)
        }
        PrivilegedOp::SetHostname { ref name } => {
            nix::unistd::sethostname(name).map_err(|err| PrivilegedOpError::HostnameChange {
                requested: name.into(),
                err,
            })
        }
    }
}
