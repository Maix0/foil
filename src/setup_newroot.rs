use std::ffi::{CStr, OsStr, OsString};
use std::os::fd::{AsFd as _, AsRawFd, FromRawFd, OwnedFd, RawFd};

use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::retry;
use crate::types::{SetupOpFlag, SetupOpType};
use crate::{
    die, die_with_error, errno,
    privilged_op::{self, privileged_op, PrivilegedOp},
    types::{
        copy_file_data, create_file, ensure_dir, ensure_file, get_newroot_path, mkdir_with_parents,
        strconcat, strconcat3, BindOptions, SetupOp,
    },
    OsString,
};

use bstr::{BStr, ByteSlice};
use nix::sys::stat::Mode;
use nix::NixPath as _;
use SetupOpType as ST;

static COVER_PROC_DIR: &'static [&'static CStr] = &[c"sys", c"sysrq-trigger", c"irq", c"bus"];
static DEV_NODES: &'static [&'static CStr] =
    &[c"null", c"zero", c"full", c"random", c"urandom", c"tty"];
static STDIO_NODES: &'static [&'static CStr] = &[c"stdin", c"stdout", c"stderr"];

fn write_options(buf: &mut OsString, options: &BStr) -> std::fmt::Result {
    use std::fmt::Write;
    for c in options.chars() {
        match c {
            '\\' | ':' | ',' => {
                write!(buf, "\\{}", c)?;
            }
            _ => {
                write!(buf, "{}", c)?;
            }
        }
    }
    Ok(())
}

pub fn oldroot_path(p: impl AsRef<Path>) -> PathBuf {
    fn oldroot_path_inner(p: &Path) -> PathBuf {
        let mut ostring = OsString::from("/oldroot/");
        ostring.push(p);
        PathBuf::from(ostring)
    }

    oldroot_path_inner(p.as_ref())
}

pub fn newroot_path(p: impl AsRef<Path>) -> PathBuf {
    fn newroot_path_inner(p: &Path) -> PathBuf {
        let mut ostring = OsString::from("/newroot/");
        ostring.push(p);
        PathBuf::from(ostring)
    }

    newroot_path_inner(p.as_ref())
}

pub fn file_mode(p: impl AsRef<Path>) -> Result<nix::sys::stat::Mode, nix::errno::Errno> {
    fn file_mode_inner(p: &Path) -> Result<nix::sys::stat::Mode, nix::errno::Errno> {
        nix::sys::stat::stat(p)
            .map(|s| nix::sys::stat::Mode::from_bits_truncate(s.st_mode & libc::S_IFMT))
    }

    file_mode_inner(p.as_ref())
}

pub fn mkdir_with_parents_rust(
    p: impl AsRef<Path>,
    mode: Mode,
    create_last: bool,
) -> std::io::Result<()> {
    pub fn mkdir_with_parents_inner(
        mut p: &Path,
        mode: Mode,
        create_last: bool,
    ) -> std::io::Result<()> {
        if !create_last {
            p = match p.parent() {
                Some(parent) => parent,
                None => return Ok(()),
            };
        }

        std::fs::DirBuilder::new().mode(mode.bits()).create(p)
    }

    mkdir_with_parents_inner(p.as_ref(), mode, create_last)
}

fn write_to_fd(fd: std::os::fd::BorrowedFd<'_>, mut content: &[u8]) -> nix::Result<()> {
    while !content.is_empty() {
        let res = nix::unistd::write(fd, content);
        if res == Err(nix::errno::Errno::EINTR) {
            continue;
        }
        match res {
            Ok(0) => return Err(nix::errno::Errno::ENOSPC),
            Err(e) => return Err(e),
            Ok(val) => content = &content[val..],
        }
    }
    Ok(())
}

fn create_file_rust(
    p: impl AsRef<Path>,
    mode: Mode,
    content: Option<impl AsRef<[u8]>>,
) -> nix::Result<()> {
    fn create_file_inner(p: &Path, mode: Mode, content: Option<&[u8]>) -> nix::Result<()> {
        let file = match p.with_nix_path(|p| {
            match retry!(unsafe { libc::creat(p.as_ptr(), mode.bits()) }) {
                -1 => Err(nix::errno::Errno::last()),
                fd => Ok(fd),
            }
        }) {
            Err(e) | Ok(Err(e)) => Err(e),
            Ok(Ok(fd)) => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
        }?;

        if let Some(data) = content {
            write_to_fd(file.as_fd(), data)?;
        }
        Ok(())
    }

    create_file_inner(p.as_ref(), mode, content.as_ref().map(|s| s.as_ref()))
}
const fn S_ISTYPE(mode: u32, mask: u32) -> bool {
    (mode & libc::S_IFMT) == mask
}

fn ensure_file_rust(p: impl AsRef<Path>, mode: Mode) -> nix::Result<()> {
    fn ensure_file_inner(p: &Path, mode: Mode) -> nix::Result<()> {
        if let Ok(stat) = nix::sys::stat::stat(p) {
            if !S_ISTYPE(stat.st_mode, libc::S_IFDIR) && !S_ISTYPE(stat.st_mode, libc::S_IFLNK) {
                return Ok(());
            }
        }

        match create_file_rust(p, mode, Option::<&[u8]>::None) {
            Ok(_) | Err(nix::errno::Errno::EEXIST) => Ok(()),
            Err(e) => Err(e),
        }
    }

    ensure_file_inner(p.as_ref(), mode)
}

fn ensure_dir_rust(p: impl AsRef<Path>, mode: Mode) -> nix::Result<()> {
    fn ensure_dir_inner(p: &Path, mode: Mode) -> nix::Result<()> {
        if let Ok(stat) = nix::sys::stat::stat(p) {
            if !S_ISTYPE(stat.st_mode, libc::S_IFDIR) {
                return Err(nix::errno::Errno::ENOTDIR);
            }
        }

        match nix::unistd::mkdir(p, mode) {
            Ok(_) | Err(nix::errno::Errno::EEXIST) => Ok(()),
            Err(e) => Err(e),
        }
    }

    ensure_dir_inner(p.as_ref(), mode)
}

pub unsafe fn setup_newroot(ops: &mut [SetupOp], unshare_pid: bool, privileged_op_socket: RawFd) {
    let mut tmp_overlay_idx = 0;
    let mut op_iterator = ops.iter_mut().peekable();

    while let Some(op) = op_iterator.next() {
        let mut source = std::ptr::null_mut() as *mut libc::c_char;

        let src_ = match op
            .src()
            .filter(|_| matches!(op, SetupOp::MakeSymlink { .. }))
            .map(|src| -> Result<_, nix::errno::Errno> {
                let p = oldroot_path(&src);
                Ok((p, file_mode(&p)?))
            }) {
            Some(Ok(s)) => Some(s),
            Some(Err(e)) if op.allow_not_exist() && e == nix::errno::Errno::ENOENT => continue,
            Some(Err(e)) => {
                panic!("couldn't get mode for {:?}: {e}", op.src().unwrap());
            }
            None => None,
        };

        let dest_ = match op
            .dest()
            .filter(|_| op.create_dest())
            .map(|dest| -> std::io::Result<_> {
                let mut parent_mode = Mode::from_bits_truncate(0o755);
                if let Some(p) = op.perms() {
                    if !p.contains(Mode::from_bits_truncate(0o070)) {
                        parent_mode &= !Mode::from_bits_truncate(0o050);
                    }
                    if !p.contains(Mode::from_bits_truncate(0o007)) {
                        parent_mode &= !Mode::from_bits_truncate(0o005);
                    }
                }
                let dest = newroot_path(&dest);
                mkdir_with_parents_rust(&dest, parent_mode, false)?;

                Ok(dest)
            }) {
            Some(Ok(dest)) => Some(dest),
            Some(Err(e)) => panic!("TODO: failed to create dirs: {e}"),
            None => None,
        };

        match (op, src_, dest_) {
            (
                SetupOp::RoBindMount { dest: rdest, .. }
                | SetupOp::BindMount { dest: rdest, .. }
                | SetupOp::DevBindMount { dest: rdest, .. },
                Some((src, src_perms)),
                Some(dest),
            ) => {
                if src_perms.bits() == libc::S_IFDIR {
                    if let Err(e) = ensure_dir_rust(dest, Mode::from_bits_truncate(0o755)) {
                        panic!("TODO: Can't mkdir {:?}: {e} ", rdest);
                    }
                } else if let Err(e) = ensure_file_rust(dest, Mode::from_bits_truncate(0o444)) {
                    panic!("TODO: Can't create file {:?}: {e} ", rdest);
                }
                privileged_op(
                    privileged_op_socket.as_raw_fd(),
                    PrivilegedOp::BindMount {
                        src,
                        dest,
                        flags: match op {
                            SetupOp::RoBindMount { .. } => BindOptions::BIND_READONLY,
                            SetupOp::DevBindMount { .. } => BindOptions::BIND_DEVICES,
                            _ => BindOptions::empty(),
                        },
                    },
                );
                if op.fd >= 0 {
                    let mut fd_st = std::mem::zeroed();
                    let mut mount_st = std::mem::zeroed();
                    if libc::fstat(op.fd, &mut fd_st) != 0 {
                        die_with_error!(c"Can't stat fd %d".as_ptr(), op.fd,);
                    }
                    if libc::lstat(dest, &mut mount_st) != 0 {
                        die_with_error!(c"Can't stat mount at %s".as_ptr(), dest,);
                    }
                    if fd_st.st_ino != mount_st.st_ino || fd_st.st_dev != mount_st.st_dev {
                        die_with_error!(c"Race condition binding dirfd".as_ptr() as *const u8
                            as *const libc::c_char,);
                    }
                    libc::close(op.fd);
                    op.fd = -1;
                }
            }
        }

        match op.kind {
            ST::RoBindMount | ST::DevBindMount | ST::BindMount => {}
            ST::TmpOverlayMount | ST::RoOverlayMount | ST::OverlayMount => {
                use std::fmt::Write;
                let mut options = OsString::new();
                if ensure_dir(dest, 0o755) != 0 {
                    die_with_error!(c"Can't mkdir %s".as_ptr(), op.dest,);
                }
                if !(op.source).is_null() {
                    write!(&mut options, "upperdir=/oldroot");
                    write_options(&mut options, OsString![op.source].as_bytes().into());
                    write!(&mut options, ",workdir=/oldroot");
                    let Some(op) = op_iterator.next() else {
                        panic!("TODO: buuble up error");
                    };
                    write_options(&mut options, OsString![op.source].as_bytes().into());
                    write!(&mut options, ",");
                } else if op.kind == ST::TmpOverlayMount {
                    let idx = tmp_overlay_idx;
                    tmp_overlay_idx = tmp_overlay_idx + 1;
                    write!(
                        &mut options,
                        "upperdir=/tmp-overlay-upper-{idx},workdir=/tmp-overlay-work-{idx},"
                    );
                }
                write!(&mut options, "lowerdir=/oldroot");
                let mut multi_src = false;
                while Some(ST::OverlaySrc) == op_iterator.peek().map(|o| o.kind) {
                    let Some(op) = op_iterator.next() else {
                        unreachable!("we just peeked the iterator ?!")
                    };
                    if multi_src {
                        write!(&mut options, ":/oldroot");
                    }
                    write_options(&mut options, OsString![op.source].as_bytes().into());
                    multi_src = true;
                }
                write!(&mut options, ",userxattr");
                privileged_op(
                    privileged_op_socket.as_raw_fd(),
                    PrivilegedOp::OverlayMount {
                        path: OsString![dest].into(),
                        options,
                    },
                );
            }
            ST::RemountRoNoRecursive => {
                privileged_op(
                    privileged_op_socket.as_raw_fd(),
                    PrivilegedOp::ReadOnlyRemount {
                        path: OsString![dest].into(),
                    },
                );
            }
            ST::MountProc => {
                if ensure_dir(dest, 0o755) != 0 {
                    panic!("Can't mkdir {:?}", unsafe { CStr::from_ptr(op.dest) });
                }
                if unshare_pid || crate::types::opt_pidns_fd != -1 {
                    privileged_op(
                        privileged_op_socket.as_raw_fd(),
                        PrivilegedOp::ProcMount {
                            path: OsString![dest].into(),
                        },
                    );
                } else {
                    privileged_op(
                        privileged_op_socket.as_raw_fd(),
                        PrivilegedOp::BindMount {
                            src: "oldroot/proc".into(),
                            dest: OsString![dest].into(),
                            flags: BindOptions::empty(),
                        },
                    );
                }
                for &elem in COVER_PROC_DIR {
                    let subdir = crate::types::strconcat3(dest, c"/".as_ptr(), elem.as_ptr());
                    if libc::access(subdir, libc::W_OK) < 0 {
                        if !(errno!() == libc::EACCES
                            || errno!() == libc::ENOENT
                            || errno!() == libc::EROFS)
                        {
                            die_with_error!(c"Can't access %s".as_ptr(), subdir,);
                        }
                    } else {
                        privileged_op(
                            privileged_op_socket.as_raw_fd(),
                            PrivilegedOp::BindMount {
                                src: OsString![subdir].into(),
                                dest: OsString![subdir].into(),
                                flags: BindOptions::BIND_READONLY,
                            },
                        );
                    }
                }
            }
            ST::MountDev => {
                if ensure_dir(dest, 0o755) != 0 {
                    die_with_error!(c"Can't mkdir %s".as_ptr(), op.dest,);
                }
                privileged_op(
                    privileged_op_socket.as_raw_fd(),
                    PrivilegedOp::TmpfsMount {
                        size: None,
                        perms: 0o755,
                        path: OsString![dest].into(),
                    },
                );
                for &elem in DEV_NODES {
                    let node_dest = strconcat3(dest, c"/".as_ptr(), elem.as_ptr());
                    let node_src = strconcat(c"/oldroot/dev/".as_ptr(), elem.as_ptr());
                    if create_file(
                        node_dest,
                        0o444,
                        std::ptr::null_mut() as *const libc::c_char,
                    ) != 0
                    {
                        panic!("Can't create file {:?}/{:?}", op.dest, elem);
                    }
                    privileged_op(
                        privileged_op_socket.as_raw_fd(),
                        PrivilegedOp::BindMount {
                            src: OsString![node_src].into(),
                            dest: OsString![node_dest].into(),
                            flags: BindOptions::BIND_DEVICES,
                        },
                    );
                }
                for (idx, &elem) in STDIO_NODES.iter().enumerate() {
                    use std::fmt::Write;
                    let mut target = OsString::new();
                    write!(&mut target, "/proc/self/fd/{idx}");
                    let real_dest = strconcat3(dest, c"/".as_ptr(), elem.as_ptr());
                    nix::unistd::symlinkat(target.as_os_str(), None, unsafe {
                        CStr::from_ptr(real_dest)
                    })
                    .expect("TODO: bubble up error");
                }
                let dev_fd = strconcat(dest, c"/fd".as_ptr());
                if libc::symlink(c"/proc/self/fd".as_ptr(), dev_fd) < 0 {
                    panic!("Can't create symlink {:?}", unsafe {
                        CStr::from_ptr(dev_fd)
                    });
                }
                let dev_core = strconcat(dest, c"/core".as_ptr());
                if libc::symlink(c"/proc/kcore".as_ptr(), dev_core) < 0 {
                    panic!("Can't create symlink {:?}", unsafe {
                        CStr::from_ptr(dev_core)
                    });
                }
                let pts = strconcat(dest, c"/pts".as_ptr());
                let ptmx = strconcat(dest, c"/ptmx".as_ptr());
                let shm = strconcat(dest, c"/shm".as_ptr());
                if libc::mkdir(shm, 0o755) == -1 {
                    die_with_error!(c"Can't create %s/shm".as_ptr(), op.dest,);
                }
                if libc::mkdir(pts, 0o755) == -1 {
                    die_with_error!(c"Can't create %s/devpts".as_ptr(), op.dest,);
                }
                privileged_op(
                    privileged_op_socket.as_raw_fd(),
                    PrivilegedOp::DevMount {
                        path: OsString![pts].into(),
                    },
                );
                if libc::symlink(c"pts/ptmx".as_ptr(), ptmx) != 0 {
                    die_with_error!(c"Can't make symlink at %s/ptmx".as_ptr(), op.dest,);
                }
                if !crate::types::host_tty_dev.is_null()
                    && *crate::types::host_tty_dev as libc::c_int != 0
                {
                    let src_tty_dev = strconcat(c"/oldroot".as_ptr(), crate::types::host_tty_dev);
                    let dest_console = strconcat(dest, c"/console".as_ptr());
                    if create_file(
                        dest_console,
                        0o444,
                        std::ptr::null_mut() as *const libc::c_char,
                    ) != 0
                    {
                        die_with_error!(c"creating %s/console".as_ptr(), op.dest,);
                    }
                    privileged_op(
                        privileged_op_socket.as_raw_fd(),
                        PrivilegedOp::BindMount {
                            src: OsString![src_tty_dev].into(),
                            dest: OsString![dest_console].into(),
                            flags: BindOptions::BIND_DEVICES,
                        },
                    );
                }
            }
            ST::MountTmpfs => {
                assert!(!dest.is_null());
                assert!(op.perms >= 0);
                assert!(op.perms <= 0o7777);
                if ensure_dir(dest, 0o755) != 0 {
                    panic!("Can't mkdir {:?}", unsafe { CStr::from_ptr(op.dest) });
                }
                privileged_op(
                    privileged_op_socket.as_raw_fd(),
                    PrivilegedOp::TmpfsMount {
                        size: std::num::NonZeroUsize::new(op.size),
                        perms: (op.perms) as _,
                        path: OsString![dest].into(),
                    },
                );
            }
            ST::MountMqueue => {
                if ensure_dir(dest, 0o755) != 0 {
                    panic!("Can't mkdir {:?}", unsafe { CStr::from_ptr(op.dest) });
                }
                privileged_op(
                    privileged_op_socket.as_raw_fd(),
                    PrivilegedOp::MqueueMount {
                        path: OsString![dest].into(),
                    },
                );
            }
            ST::MakeDir => {
                assert!(!dest.is_null());
                assert!(op.perms >= 0);
                assert!(op.perms <= 0o7777);
                if ensure_dir(dest, op.perms as libc::mode_t) != 0 {
                    panic!("Can't mkdir {:?}", unsafe { CStr::from_ptr(op.dest) });
                }
            }
            ST::Chmod => {
                assert!(!(op.dest).is_null());
                assert!(dest.is_null());
                dest = get_newroot_path(op.dest);
                assert!(!dest.is_null());
                assert!(op.perms >= 0);
                assert!(op.perms <= 0o7777);
                if libc::chmod(dest, op.perms as libc::mode_t) != 0 {
                    panic!("Can't chmod {:#o} {:?}", op.perms, unsafe {
                        CStr::from_ptr(op.dest)
                    });
                }
            }
            ST::MakeFile => {
                let mut dest_fd = -1;
                assert!(!dest.is_null());
                assert!(op.perms >= 0);
                assert!(op.perms <= 0o7777);
                dest_fd = libc::creat(dest, op.perms as libc::mode_t);
                if dest_fd == -1 {
                    die_with_error!(c"Can't create file %s".as_ptr(), op.dest,);
                }
                if crate::types::copy_file_data(op.fd, dest_fd) != 0 {
                    die_with_error!(
                        c"Can't write data to file %s".as_ptr() as *const u8 as *const libc::c_char,
                        op.dest,
                    );
                }
                libc::close(op.fd);
                op.fd = -1;
            }
            ST::MakeBindFile | ST::MakeRoBindFile => {
                assert!(!dest.is_null());
                assert!(op.perms >= 0);
                assert!(op.perms <= 0o7777);
                let (dest_fd, tempfile) =
                    nix::unistd::mkstemp(c"/bindfileXXXXXX").expect("TODO: bubble up error");
                if let Err(e) = nix::sys::stat::fchmod(
                    dest_fd,
                    nix::sys::stat::Mode::from_bits_retain(op.perms as _),
                ) {
                    panic!(
                        "Can't set mode {:#o} on file to be used for {:?}: {e}",
                        op.perms,
                        unsafe { CStr::from_ptr(op.dest) },
                    );
                }
                if copy_file_data(op.fd, dest_fd) != 0 {
                    panic!("Can't write data to file {:?}", unsafe {
                        CStr::from_ptr(op.dest)
                    });
                }
                nix::unistd::close(op.fd);
                op.fd = -1;
                assert!(!dest.is_null());
                if ensure_file(dest, 0o444) != 0 {
                    panic!("Can't create file at {:?}", unsafe {
                        CStr::from_ptr(op.dest)
                    });
                }
                privileged_op(
                    privileged_op_socket.as_raw_fd(),
                    privilged_op::PrivilegedOp::BindMount {
                        src: tempfile.clone(),
                        dest: OsString![dest].into(),
                        flags: (if op.kind == ST::MakeRoBindFile {
                            BindOptions::BIND_READONLY
                        } else {
                            BindOptions::empty()
                        }),
                    },
                );
                nix::unistd::unlink(tempfile.as_path());
            }
            ST::MakeSymlink => {
                assert!(!(op.source).is_null());
                if libc::symlink(op.source, dest) != 0 {
                    if errno!() == libc::EEXIST {
                        let existing = crate::types::readlink_malloc(dest);
                        if existing.is_null() {
                            if errno!() == libc::EINVAL {
                                crate::die!(
                                            c"Can't make symlink at %s: destination exists and is not a symlink".as_ptr()
                                                as *const u8 as *const libc::c_char,
                                            op.dest,
                                        );
                            } else {
                                die_with_error!(
                                            c"Can't make symlink at %s: destination exists, and cannot read symlink target".as_ptr()
                                                as *const u8 as *const libc::c_char,
                                            op.dest,
                                        );
                            }
                        }
                        if !(libc::strcmp(existing, op.source) == 0) {
                            die!(
                                c"Can't make symlink at %s: existing destination is %s".as_ptr()
                                    as *const u8
                                    as *const libc::c_char,
                                op.dest,
                                existing,
                            );
                        }
                    } else {
                        die_with_error!(
                            c"Can't make symlink at %s".as_ptr() as *const u8
                                as *const libc::c_char,
                            op.dest,
                        );
                    }
                }
            }
            ST::SetHostname => {
                assert!(!(op.dest).is_null());
                privileged_op(
                    privileged_op_socket.as_raw_fd(),
                    privilged_op::PrivilegedOp::SetHostname {
                        name: OsString![op.dest],
                    },
                );
            }
            ST::OverlaySrc | _ => {
                die!(c"Unexpected type %d".as_ptr(), op.kind,);
            }
        }
    }
    privileged_op(
        privileged_op_socket.as_raw_fd(),
        privilged_op::PrivilegedOp::Done,
    );
}
