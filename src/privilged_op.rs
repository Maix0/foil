use std::{
    ffi::{CStr, OsStr},
    os::unix::ffi::OsStrExt as _,
};

use nix::{mount::MsFlags, NixPath};

use crate::{
    bind_mount::bind_mount,
    die_with_bind_result, errno,
    types::{opt_unshare_uts, proc_fd, BindOptions, MAX_TMPFS_BYTES},
};

pub unsafe fn privileged_op<P1: NixPath, P2: NixPath>(
    op: u32,
    flags: BindOptions,
    perms: u32,
    size_arg: usize,
    arg1: P1,
    arg2: P2,
) {
    arg1.with_nix_path(|arg1| {
        arg2.with_nix_path(|arg2| {
    match op {
        0 => {}
        7 => {
            let bind_result = bind_mount(
                proc_fd,
                Option::<&str>::None,
                arg2,
                BindOptions::BIND_READONLY,
            );
            if let Err(e) = &bind_result {
                die_with_bind_result!(
                    &bind_result,
                    errno!(),
                    e,
                    c"Can't remount readonly on {arg2}: {e}".as_ptr(),
                );
            }
        }
        1 => {
            let bind_result = bind_mount(
                proc_fd,
                Some(arg1),
                arg2,
                BindOptions::BIND_RECURSIVE | flags,
            );
            if let Err(e) = &bind_result {
                die_with_bind_result!(
                    &bind_result,
                    errno!(),
                    e,
                    c"Can't bind mount %s on %s".as_ptr(),
                    arg1,
                    arg2,
                );
            }
        }
        3 => {
            if let Err(e) = nix::mount::mount(
                Some(c"proc"),
                arg1,
                Some(c"proc"),
                MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
                Option::<&str>::None,
            ) {
                panic!("Can't mount proc on {arg1:?}: {e}");
            }
        }
        4 => {
            if size_arg > MAX_TMPFS_BYTES as usize {
                panic!("Specified tmpfs size too large ({size_arg} > {MAX_TMPFS_BYTES})");
            }
            let mode = if size_arg != 0 {
                 format!("mode={perms:#o},size={size_arg}")
            } else {
                 format!("mode={perms:#o}")
            };
            if let Err(e) = nix::mount::mount(
                Some(c"tmpfs"),
                arg1,
                Some(c"tmpfs"),
                MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                Some(mode.as_str())
            )
            {
                panic!("Can't mount tmpfs on {arg1:?}: {e}");
            }
        }
        5 => {
            if let Err(e) = nix::mount::mount(
                Some(c"devpts"),
                arg1,
                Some(c"devpts"),
                MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                Some(c"newinstance,ptmxmode=0666,mode=620"),
            )
            {
                panic!("Can't mount devpts on {arg1:?}: {e}");
            }
        }
        6 => {
            if let Err(e)=  nix::mount::mount(
                Some(c"mqueue"),
                arg1,
                Some(c"mqueue"),
                MsFlags::empty(),
               Option::<&str>::None,
            )
            {
                panic!("Can't mount mqueue on {arg1:?}: {e}");
            }
        }
        2 => {
            if let Err(e) = nix::mount::mount(
                Some(c"overlay"),
                arg2,
                Some(c"overlay"),
                nix::mount::MsFlags::MS_MGC_VAL ,
                Some(arg1),
            )
            {
                if e == nix::errno::Errno::ELOOP {
                    panic!("Can't make overlay mount on {arg2:?} with options {arg1:?}: Overlay directories may not overlap");
                }
                panic!("Can't make overlay mount on {arg2:?} with options {arg1:?}: {e}");
            }
        }
        8 => {
            if !opt_unshare_uts {
                panic!("Refusing to set hostname in original namespace");
            }
            if let Err(e) = nix::unistd::sethostname(OsStr::from_bytes(arg1.to_bytes())) {
                panic!("Can't set hostname to {arg1:?}: {e}");
            }
        }
        _ => {
            panic!("Unexpected privileged op {op}");
        }
    }
        }).unwrap();
    });
}
