use std::{
    ffi::OsString,
    num::NonZeroUsize,
    os::fd::{BorrowedFd, RawFd},
};

use nix::mount::MsFlags;

use crate::{
    bind_mount::{bind_mount, BindMountError, BindOptions},
    nix_retry,
    types::{opt_unshare_uts, proc_fd},
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
        #[serde(with = "crate::serde_errno")]
        err: nix::errno::Errno,
    },
    TmpfsTooBig {
        path: std::path::PathBuf,
        requested_size: NonZeroUsize,
    },
    TmpfsMount {
        path: std::path::PathBuf,
        #[serde(with = "crate::serde_errno")]
        err: nix::errno::Errno,
    },
    DevMount {
        path: std::path::PathBuf,
        #[serde(with = "crate::serde_errno")]
        err: nix::errno::Errno,
    },
    MqueueMount {
        path: std::path::PathBuf,
        #[serde(with = "crate::serde_errno")]
        err: nix::errno::Errno,
    },
    OverlayMount {
        path: std::path::PathBuf,
        #[serde(with = "crate::serde_errno")]
        err: nix::errno::Errno,
        options: OsString,
    },
    HostnameChange {
        requested: OsString,
        #[serde(with = "crate::serde_errno")]
        err: nix::errno::Errno,
    },
    HostnameNotUnshared,
    UnknownCommand,
    PrivilegedProcessCommunicationError,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
/*
    uint32_t buffer[2048]; /* 8k, but is int32 to guarantee nice alignment */
    PrivSepOp *op_buffer = (PrivSepOp *)buffer;
    size_t buffer_size = sizeof(PrivSepOp);
    uint32_t arg1_offset = 0, arg2_offset = 0;

    /* We're unprivileged, send this request to the privileged part */

    if (arg1 != NULL) {
      arg1_offset = buffer_size;
      buffer_size += strlen(arg1) + 1;
    }
    if (arg2 != NULL) {
      arg2_offset = buffer_size;
      buffer_size += strlen(arg2) + 1;
    }

    if (buffer_size >= sizeof(buffer))
      die("privilege separation operation to large");

    op_buffer->op = op;
    op_buffer->flags = flags;
    op_buffer->perms = perms;
    op_buffer->size_arg = size_arg;
    op_buffer->arg1_offset = arg1_offset;
    op_buffer->arg2_offset = arg2_offset;
    if (arg1 != NULL)
      strcpy((char *)buffer + arg1_offset, arg1);
    if (arg2 != NULL)
      strcpy((char *)buffer + arg2_offset, arg2);

    if (TEMP_FAILURE_RETRY(write(privileged_op_socket, buffer, buffer_size)) !=
        (ssize_t)buffer_size)
      die("Can't write to privileged_op_socket");

    if (TEMP_FAILURE_RETRY(read(privileged_op_socket, buffer, 1)) != 1)
      die("Can't read from privileged_op_socket");

    return;
*/

fn send_priviledged_op(privileged_op_fd: RawFd, op: PrivilegedOp) -> Result<(), PrivilegedOpError> {
    let val = postcard::to_stdvec(&op)
        .map_err(|_| PrivilegedOpError::PrivilegedProcessCommunicationError)?;

    let _wres = nix_retry!(nix::unistd::write(
        unsafe { BorrowedFd::borrow_raw(privileged_op_fd) },
        val.as_slice()
    ))
    .map_err(|_| PrivilegedOpError::PrivilegedProcessCommunicationError)?;

    let mut buffer = val;
    buffer.clear();
    buffer.resize(8096, 0);

    let rres = nix_retry!(nix::unistd::read(privileged_op_fd, buffer.as_mut_slice()))
        .map_err(|_| PrivilegedOpError::PrivilegedProcessCommunicationError)?;

    postcard::from_bytes(&buffer[..rres])
        .map_err(|_| PrivilegedOpError::PrivilegedProcessCommunicationError)?
}

pub const MAX_TMPFS_BYTES: NonZeroUsize = NonZeroUsize::new(usize::MAX >> 1).unwrap();

pub fn privileged_op(privileged_op_fd: RawFd, op: PrivilegedOp) -> Result<(), PrivilegedOpError> {
    if privileged_op_fd != -1 {
        return send_priviledged_op(privileged_op_fd, op);
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
