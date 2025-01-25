use std::ffi::OsString;
use std::os::fd::{AsFd as _, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::unreachable;

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::retry;
use crate::{
    errno,
    privilged_op::{self, privileged_op, PrivilegedOp},
    types::{
        BindOptions,
        SetupOp,
    },
};

use bitflags::Flags;
use bstr::{BStr, ByteSlice};
use nix::errno::Errno;
use nix::sys::stat::Mode;
use nix::unistd::AccessFlags;
use nix::NixPath as _;

macro_rules! push_path {
    ($base:expr, $($e:expr),* $(,)?) => {
        {
        let mut out: std::path::PathBuf = $base;
        $(
            out.push($e);
        )*
        out
        }
    };
}

static COVER_PROC_DIR: &'static [&'static str] = &["sys", "sysrq-trigger", "irq", "bus"];
static DEV_NODES: &'static [&'static str] = &["null", "zero", "full", "random", "urandom", "tty"];
static STDIO_NODES: &'static [&'static str] = &["stdin", "stdout", "stderr"];

fn get_newroot_path_rust(path: impl AsRef<Path>) -> PathBuf {
    fn _inner(path: &Path) -> PathBuf {
        let mut out = PathBuf::from("/newroot/");
        for c in path.components().filter(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Prefix(_)
            )
        }) {
            out.push(c)
        }
        out
    }

    _inner(path.as_ref())
}

fn get_oldroot_path_rust(path: impl AsRef<Path>) -> PathBuf {
    fn _inner(path: &Path) -> PathBuf {
        let mut out = PathBuf::from("/oldroot/");
        for c in path.components().filter(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Prefix(_)
            )
        }) {
            out.push(c)
        }
        out
    }

    _inner(path.as_ref())
}

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

fn copy_file_data_rust(src: BorrowedFd<'_>, dest: BorrowedFd<'_>) -> nix::Result<usize> {
    let mut buffer = [0u8; 8096];
    let mut total = 0;
    loop {
        let b = match nix::unistd::read(src.as_raw_fd(), &mut buffer[..]) {
            Ok(n) => {
                total += n;
                &buffer[..n]
            }
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e),
        };
        nix::unistd::write(dest, b)?;
        if b.len() != buffer.len() {
            return Ok(total);
        }
    }
}

macro_rules! get_src {
    ($src:expr, $allow_not_exist:expr) => {{
        match (|src| -> nix::Result<_> {
            let p = oldroot_path(&src);
            let mode = file_mode(&p)?;
            Ok((p, mode))
        })($src)
        {
            Ok(s) => s,
            Err(e) if $allow_not_exist && e == nix::errno::Errno::ENOENT => continue,
            Err(e) => {
                panic!("couldn't get mode for {}: {e}", ($src).display());
            }
        }
    }};
}

macro_rules! get_dest {
    ($dest:expr, $perms:expr) => {{
        match (|dest, perms: Option<Mode>| -> std::io::Result<_> {
            let mut parent_mode = Mode::from_bits_truncate(0o755);
            if let Some(p) = perms {
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
        })($dest, $perms)
        {
            Ok(dest) => dest,
            Err(e) => panic!("TODO: failed to create dirs: {e}"),
        }
    }};
}

pub fn setup_newroot(state: &mut crate::foil::State, privileged_op_socket: Option<RawFd>) {
    let mut tmp_overlay_idx = 0;
    let ops = std::mem::take(&mut state.operations);
    let mut op_iterator = ops.iter().peekable();

    while let Some(op) = op_iterator.next() {
        match op {
            SetupOp::RoBindMount {
                dest,
                src,
                allow_not_exist,
                perms,
            }
            | SetupOp::BindMount {
                dest,
                src,
                allow_not_exist,
                perms,
            }
            | SetupOp::DevBindMount {
                dest,
                src,
                allow_not_exist,
                perms,
            } => {
                let (src, src_perms) = get_src!(src, *allow_not_exist);
                let dest = get_dest!(dest, *perms);
                if src_perms.bits() == libc::S_IFDIR {
                    if let Err(e) = ensure_dir_rust(&dest, Mode::from_bits_truncate(0o755)) {
                        panic!("TODO: Can't mkdir {}: {e} ", dest.display());
                    }
                } else if let Err(e) = ensure_file_rust(&dest, Mode::from_bits_truncate(0o444)) {
                    panic!("TODO: Can't create file {}: {e} ", dest.display());
                }
                privileged_op(
                    state,
                    privileged_op_socket,
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
            }

            op @ (SetupOp::RoOverlayMount { dest, perms, .. }
            | SetupOp::OverlayMount { dest, perms, .. }
            | SetupOp::TmpOverlayMount { dest, perms }) => {
                use std::fmt::Write;
                let mut options = OsString::new();
                let dest = get_dest!(dest, *perms);
                let source = match &op {
                    SetupOp::TmpOverlayMount { .. } => None,
                    SetupOp::RoOverlayMount { src, .. } | SetupOp::OverlayMount { src, .. } => {
                        Some(get_src!(src, false))
                    }
                    _ => unreachable!(),
                };
                ensure_dir_rust(&dest, Mode::from_bits_truncate(0o755))
                    .expect("TODO: Can't mkdir dest");
                if let Some((src, _)) = source.as_ref() {
                    write!(&mut options, "upperdir=/oldroot");
                    write_options(&mut options, src.as_os_str().as_bytes().into());
                    write!(&mut options, ",workdir=/oldroot");
                    let Some(op_src) = op_iterator.next().map(|o| o.src()).flatten() else {
                        panic!("TODO: buuble up error");
                    };
                    write_options(&mut options, op_src.as_os_str().as_bytes().into());
                    write!(&mut options, ",");
                } else if let &SetupOp::TmpOverlayMount { .. } = &op {
                    let idx = tmp_overlay_idx;
                    tmp_overlay_idx = tmp_overlay_idx + 1;
                    write!(
                        &mut options,
                        "upperdir=/tmp-overlay-upper-{idx},workdir=/tmp-overlay-work-{idx},"
                    );
                }
                write!(&mut options, "lowerdir=/oldroot");
                let mut multi_src = false;
                while let Some(&SetupOp::OverlaySrc { .. }) = op_iterator.peek() {
                    let Some(SetupOp::OverlaySrc { src, .. }) = op_iterator.next() else {
                        unreachable!();
                    };
                    if multi_src {
                        write!(&mut options, ":/oldroot");
                    }
                    write_options(&mut options, src.as_os_str().as_bytes().into());
                    multi_src = true;
                    let _ = op_iterator.next();
                }
                write!(&mut options, ",userxattr");
                privileged_op(
                    state,
                    privileged_op_socket,
                    PrivilegedOp::OverlayMount {
                        path: dest,
                        options,
                    },
                );
            }
            SetupOp::RemountRoNoRecursive { dest, perms } => {
                let dest = get_dest!(dest, *perms);
                privileged_op(
                    state,
                    privileged_op_socket,
                    PrivilegedOp::ReadOnlyRemount { path: dest },
                );
            }
            SetupOp::MountProc { dest, perms } => {
                let dest = get_dest!(dest, *perms);
                if ensure_dir_rust(&dest, Mode::from_bits_truncate(0o755)).is_err() {
                    panic!("Can't mkdir {}", dest.display());
                }
                if state.unshare_pid {
                    privileged_op(
                        state,
                        privileged_op_socket,
                        PrivilegedOp::ProcMount { path: dest.clone() },
                    );
                } else {
                    privileged_op(
                        state,
                        privileged_op_socket,
                        PrivilegedOp::BindMount {
                            src: "oldroot/proc".into(),
                            dest: dest.clone(),
                            flags: BindOptions::empty(),
                        },
                    );
                }
                for &elem in COVER_PROC_DIR {
                    let subdir = push_path!(dest.clone(), elem);
                    if let Err(e) = nix::unistd::access(subdir.as_path(), AccessFlags::W_OK) {
                        match e {
                            Errno::EACCES | Errno::ENOENT | Errno::EROFS => {}
                            _ => panic!("TODO: Can't access {}: {e}", subdir.display()),
                        }
                    } else {
                        privileged_op(
                            state,
                            privileged_op_socket,
                            PrivilegedOp::BindMount {
                                src: subdir.clone(),
                                dest: subdir.clone(),
                                flags: BindOptions::BIND_READONLY,
                            },
                        );
                    }
                }
            }
            SetupOp::MountDev { perms, dest } => {
                let dest = get_dest!(dest, *perms);
                if ensure_dir_rust(&dest, Mode::from_bits_truncate(0o755)).is_err() {
                    panic!("Can't mkdir {}", dest.display());
                }
                privileged_op(
                    state,
                    privileged_op_socket,
                    PrivilegedOp::TmpfsMount {
                        size: None,
                        perms: 0o755,
                        path: dest.clone(),
                    },
                );
                for &elem in DEV_NODES {
                    let node_dest = push_path!(dest.clone(), elem);
                    let node_src = push_path!("/oldroot/dev/".into(), elem);

                    if let Err(e) = create_file_rust(
                        &node_dest,
                        Mode::from_bits_truncate(0o444),
                        Option::<&[u8]>::None,
                    ) {
                        panic!("Can't create file {}/{}: {e}", dest.display(), elem);
                    }
                    privileged_op(
                        state,
                        privileged_op_socket,
                        PrivilegedOp::BindMount {
                            src: node_src,
                            dest: node_dest,
                            flags: BindOptions::BIND_DEVICES,
                        },
                    );
                }
                for (idx, &elem) in STDIO_NODES.iter().enumerate() {
                    use std::fmt::Write;
                    let mut target = OsString::new();
                    write!(&mut target, "proc/self/fd/{idx}");
                    let real_dest = push_path!(dest.clone(), elem);
                    nix::unistd::symlinkat(target.as_os_str(), None, real_dest.as_path())
                        .expect("TODO: bubble up error");
                }

                let dev_fd = push_path!(dest.clone(), "fd");
                nix::unistd::symlinkat("/proc/self/fd", None, dev_fd.as_path())
                    .expect("TODO: bubble up error");
                let dev_core = push_path!(dest.clone(), "core");
                nix::unistd::symlinkat("/proc/kcore", None, dev_core.as_path())
                    .expect("TODO: bubble up error");

                let pts = push_path!(dest.clone(), "pts");
                let ptmx = push_path!(dest.clone(), "ptmx");
                let shm = push_path!(dest.clone(), "shm");
                if let Err(e) = nix::unistd::mkdir(&shm, Mode::from_bits_truncate(0o755)) {
                    panic!("TODO: Can't create {}/shm: {e}", dest.display());
                }
                if let Err(e) = nix::unistd::mkdir(&pts, Mode::from_bits_truncate(0o755)) {
                    panic!("TODO: Can't create {}/devpts: {e}", dest.display());
                }
                privileged_op(
                    state,
                    privileged_op_socket,
                    PrivilegedOp::DevMount { path: pts },
                );
                if let Err(e) = nix::unistd::symlinkat(c"pts/ptmx", None, &ptmx) {
                    panic!("TODO: Can't make symlink at {}/ptmx: {e}", dest.display());
                }
                if let Some(tty_dev) = &state.host_tty_dev {
                    let src_tty_dev = push_path!(PathBuf::from("/oldroot"), tty_dev);
                    let dest_console = push_path!(dest.clone(), "console");
                    if let Err(e) = create_file_rust(
                        &dest_console,
                        Mode::from_bits_truncate(0o444),
                        Option::<&[u8]>::None,
                    ) {
                        panic!("creating {}/console: {e}", dest.display());
                    }
                    privileged_op(
                        state,
                        privileged_op_socket,
                        PrivilegedOp::BindMount {
                            src: src_tty_dev,
                            dest: dest_console,
                            flags: BindOptions::BIND_DEVICES,
                        },
                    );
                }
            }
            SetupOp::MountTmpfs { perms, size, dest } => {
                let dest = get_dest!(dest, *perms);
                if let Err(e) = ensure_dir_rust(&dest, Mode::from_bits_truncate(0o755)) {
                    panic!("TODO: can't mkdir {}: {e}", dest.display())
                }
                privileged_op(
                    state,
                    privileged_op_socket,
                    PrivilegedOp::TmpfsMount {
                        size: *size,
                        perms: perms.map(|m| m.bits()).unwrap_or(0o755),
                        path: dest,
                    },
                );
            }

            SetupOp::MountMqueue { dest, perms } => {
                let dest = get_dest!(dest, *perms);
                if let Err(e) = ensure_dir_rust(&dest, Mode::from_bits_truncate(0o755)) {
                    panic!("TODO: can't mkdir {}: {e}", dest.display())
                }
                privileged_op(
                    state,
                    privileged_op_socket,
                    PrivilegedOp::MqueueMount { path: dest },
                );
            }
            SetupOp::MakeDir { perms, dest } => {
                let dest = get_dest!(dest, *perms);
                if let Err(e) =
                    ensure_dir_rust(&dest, perms.unwrap_or(Mode::from_bits_truncate(0o755)))
                {
                    panic!("TODO: can't mkdir {}: {e}", dest.display())
                }
            }
            SetupOp::Chmod { perms, dest } => {
                let dest = get_newroot_path_rust(&dest);
                if let Err(e) = nix::sys::stat::fchmodat(
                    None,
                    &dest,
                    perms.unwrap_or(Mode::from_bits_truncate(0o755)),
                    nix::sys::stat::FchmodatFlags::FollowSymlink,
                ) {
                    panic!("TODO: can't chmod {}: {e}", dest.display())
                }
            }
            SetupOp::MakeFile { perms, fd, dest } => {
                let dest = get_dest!(dest, *perms);
                let dest_fd = match dest.with_nix_path(|p| {
                    match unsafe {
                        libc::creat(p.as_ptr(), perms.map(|p| p.bits()).unwrap_or(0o755))
                    } {
                        -1 => Err(Errno::last()),
                        fd => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
                    }
                }) {
                    Err(e) | Ok(Err(e)) => Err(e),
                    Ok(Ok(fd)) => Ok(fd),
                };
                if let Err(e) = dest_fd {
                    panic!("Can't create file {}: {e}", dest.display());
                }
                if let Err(e) = copy_file_data_rust(fd.as_fd(), dest_fd.unwrap().as_fd()) {
                    panic!("Can't write data to file {}: {e}", dest.display());
                }
            }
            SetupOp::MakeBindFile { perms, fd, dest }
            | SetupOp::MakeRoBindFile { perms, fd, dest } => {
                let dest = get_dest!(dest, *perms);
                let (dest_fd, tempfile) =
                    nix::unistd::mkstemp(c"/bindfileXXXXXX").expect("TODO: bubble up error");
                let dest_fd = unsafe { OwnedFd::from_raw_fd(dest_fd) };
                if let Err(e) = nix::sys::stat::fchmod(
                    dest_fd.as_raw_fd(),
                    perms.unwrap_or(Mode::from_bits_truncate(0o755)),
                ) {
                    panic!(
                        "Can't set mode {:#o} on file to be used for {}: {e}",
                        perms.unwrap_or(Mode::from_bits_truncate(0o755)),
                        dest.display()
                    );
                }
                if let Err(e) = copy_file_data_rust(fd.as_fd(), dest_fd.as_fd()) {
                    panic!("Can't write data to file {}: {e}", dest.display());
                }
                drop(fd);

                if let Err(e) = ensure_file_rust(&dest, Mode::from_bits_truncate(0o444)) {
                    panic!("Can't create file at {}: {e}", dest.display());
                }
                privileged_op(
                    state,
                    privileged_op_socket,
                    privilged_op::PrivilegedOp::BindMount {
                        src: tempfile.clone(),
                        dest: dest.into(),
                        flags: (if matches!(op, SetupOp::MakeRoBindFile { .. }) {
                            BindOptions::BIND_READONLY
                        } else {
                            BindOptions::empty()
                        }),
                    },
                );
                nix::unistd::unlink(tempfile.as_path());
            }
            SetupOp::MakeSymlink { src, dest, perms } => {
                let dest = get_dest!(dest, *perms);
                match nix::unistd::symlinkat(src, None, &dest) {
                    Err(Errno::EEXIST) => {
                        let val = nix::fcntl::readlink(&dest).map(PathBuf::from);
                        if let Err(e) = val {
                            match e {
        Errno::EINVAL =>  panic!("Can't make symlink at {}: Destination exist, and is not a symlink", dest.display()),
                    e => panic!("Can't make symlink at {}: Destination exist, cannot read symlink target: {e}", dest.display()),
                        }
                        }
                        let val = val.unwrap();
                        if val != *src {
                            panic!("Can't make symlink at {}: Destination exist, and point to something {}", dest.display(), val.display());
                        }
                    }
                    Err(e) => panic!("Failed to create symlink at {} : {e}", dest.display()),
                    Ok(()) => (),
                }
            }
            SetupOp::SetHostname { hostname } => {
                privileged_op(
                    state,
                    privileged_op_socket,
                    privilged_op::PrivilegedOp::SetHostname {
                        name: hostname.clone(),
                    },
                );
            }
            _ => {
                panic!("Unknown operator")
            }
        }
    }
    privileged_op(
        state,
        privileged_op_socket,
        privilged_op::PrivilegedOp::Done,
    );
}
