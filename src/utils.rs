use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use bstr::ByteSlice;
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::{Pid, SysconfVar};
use nix::NixPath;

pub(crate) use macros::{nix_retry, libc_retry};
mod macros {
    macro_rules! nix_retry {
        ($e:expr) => {
            loop {
                let result = $e;
                if !matches!(
                    &result,
                    ::core::result::Result::Err(::nix::errno::Errno::EINTR)
                ) {
                    break result;
                }
            }
        };
    }

    macro_rules! libc_retry {
        ($e:expr) => {
            loop {
                let result = ::nix::errno::Errno::result($e);
                if !matches!(
                    &result,
                    ::core::result::Result::Err(::nix::errno::Errno::EINTR)
                ) {
                    break result;
                }
            }
        };
    }
    pub(crate) use nix_retry;
    pub(crate) use libc_retry;
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

pub fn write_to_fd_rust(
    fd: BorrowedFd<'_>,
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

pub const BUFSIZE: usize = 8192;

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
