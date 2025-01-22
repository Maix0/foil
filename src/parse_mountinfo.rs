use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::BufReader;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};

use bstr::ByteSlice;
use bstr::{io::BufReadExt, BStr, BString};

#[derive(Debug, Clone)]
struct RMountInfoLine {
    pub mountpoint: PathBuf,
    pub options: BString,
    pub covered: bool,
    pub id: i32,
    pub parent_id: i32,
    pub first_child: Option<usize>,
    pub next_sibling: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct RMountInfo {
    pub mountpoint: PathBuf,
    pub options: nix::mount::MsFlags,
}

/// This function takes a string, and returns the same string but with every \XXX converted from
/// octal to the corespoiding char code pointer
///
/// Return [`None`] in case of malformed input
fn unescape(s: impl AsRef<BStr>) -> Option<BString> {
    fn unescape_inner(s: &BStr) -> Option<BString> {
        let mut out = BString::new(Vec::with_capacity(s.len()));
        let mut chars = s.iter();
        while let Some(&c) = chars.next() {
            if c == b'\\' {
                let cs = [*chars.next()?, *chars.next()?, *chars.next()?];
                if cs.iter().any(|&c| c < b'0' || c > b'9') {
                    return None;
                }
                out.push(((cs[0] - b'0') << 6) | ((cs[1] - b'0') << 3) | (cs[2] - b'0'));
            } else {
                out.push(c);
            }
        }
        Some(out)
    }

    unescape_inner(s.as_ref())
}

fn has_path_prefix(path: impl AsRef<Path>, prefix: impl AsRef<Path>) -> bool {
    fn has_path_prefix_inner(path: &Path, prefix: &Path) -> bool {
        let mut path = path.components();
        let mut prefix = prefix.components();

        loop {
            let a = path.next();
            let b = prefix.next();

            match (a, b) {
                // both thingy match, next step
                (Some(a), Some(b)) if a == b => continue,
                // no match, can't be a prefix then
                (Some(_), Some(_)) => return false,
                // prefix has still some stuff, then it can't be a prefix
                (None, Some(_)) => return false,
                // path still has some stuff but not prefix, good
                (Some(_), None) => return true,
                // both finished, then yes its a prefix
                (None, None) => return true,
            }
        }
    }

    has_path_prefix_inner(path.as_ref(), prefix.as_ref())
}

fn decode_mountoptions(opts: impl AsRef<BStr>) -> nix::mount::MsFlags {
    fn decode_mountoptions_inner(opts: &BStr) -> nix::mount::MsFlags {
        use nix::mount::MsFlags;
        static FLAGS: phf::Map<&'static [u8], MsFlags> = phf::phf_map! {
            b"ro" => MsFlags::MS_RDONLY,
            b"nosuid" => MsFlags::MS_NOSUID,
            b"nodev" => MsFlags::MS_NODEV,
            b"noexec" => MsFlags::MS_NOEXEC,
            b"noatime" => MsFlags::MS_NOATIME,
            b"nodiratime" => MsFlags::MS_NODIRATIME,
            b"relatime" => MsFlags::MS_RELATIME,
        };
        let mut out = MsFlags::empty();

        opts.split_str(",")
            .filter_map(|tok| FLAGS.get(tok).copied())
            .for_each(|flag| out |= flag);

        out
    }

    decode_mountoptions_inner(opts.as_ref())
}

fn collect_mounts(info: &mut Vec<RMountInfo>, lines: &[RMountInfoLine], this: usize) {
    if !lines[this].covered {
        info.push(RMountInfo {
            mountpoint: lines[this].mountpoint.clone(),
            options: decode_mountoptions(&lines[this].options),
        });
    }
    let mut child = lines[this].first_child;
    while let Some(child_id) = child {
        collect_mounts(info, lines, child_id);
        child = lines[child_id].next_sibling;
    }
}

pub fn parse_mountinfo(
    proc_fd: BorrowedFd<'_>,
    root_mount: impl AsRef<OsStr>,
) -> Box<[RMountInfo]> {
    pub fn parse_mountinfo_inner(proc_fd: BorrowedFd<'_>, root_mount: &OsStr) -> Box<[RMountInfo]> {
        let Ok(mountinfo) = nix::fcntl::openat(
            Some(proc_fd.as_raw_fd()),
            "self/mountinfo",
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        )
        .map(|fd| unsafe { std::fs::File::from_raw_fd(fd) })
        .map(BufReader::new) else {
            // FIXME: bubble up error here
            panic!("Can't open /proc/self/mountinfo");
        };
        let mut mounts = Vec::<RMountInfoLine>::new();
        let mut max_id = 0;
        let mut root = None;
        for (idx, line) in mountinfo.byte_lines().enumerate() {
            let line = line.unwrap(); // FIXME: bubble up error here
            let Some(([id, parent_id, _maj, _min, _mountroot, mountpoint, options], _rest)) =
                (|| {
                    // Poor man try blocks...
                    let (w1, rest) = line.split_once_str(b" ")?;
                    let (w2, rest) = rest.split_once_str(b" ")?;
                    let (w3, rest) = rest.split_once_str(b" ")?;
                    let (w4, rest) = rest.split_once_str(b" ")?;
                    let (w5, rest) = rest.split_once_str(b" ")?;
                    let (w6, rest) = rest.split_once_str(b" ")?;

                    let tmp = w3.split_once_str(b":")?;
                    Some(([w1, w2, tmp.0, tmp.1, w4, w5, w6], rest))
                })()
            else {
                panic!("Failed to parse line of /proc/self/mountinfo");
            };
            let id: i32 = id.to_str().unwrap().parse().unwrap();
            let parent_id: i32 = parent_id.to_str().unwrap().parse().unwrap();

            let mountpoint = std::path::PathBuf::from(OsString::from_vec(
                unescape(mountpoint).unwrap().to_vec(),
            ));

            max_id = max_id.max(id).max(parent_id);
            if mountpoint == root_mount {
                root = Some(idx);
            }
            mounts.push(RMountInfoLine {
                id,
                parent_id,
                mountpoint,
                covered: false,
                first_child: None,
                next_sibling: None,
                options: options.into(),
            });
        }

        if root.is_none() {
            return Vec::new().into_boxed_slice();
        }
        let root = root.unwrap();

        let mut by_id = HashMap::with_capacity(mounts.len());

        for (idx, tab) in mounts.iter().enumerate() {
            by_id.insert(tab.id, idx);
        }

        let len = mounts.len();

        for this in 0..len {
            // can't borrow since it wouldn't allow us to modify the parent
            let Some(parent) = by_id.get(&mounts[this].parent_id).copied() else {
                continue;
            };

            if !has_path_prefix(&mounts[this].mountpoint, root_mount) {
                continue;
            }

            if mounts[parent].mountpoint == mounts[this].mountpoint {
                mounts[parent].covered = true;
            }

            enum FillSibling {
                FistChild,
                NextSibling,
            }

            let mut covered = false;
            let mut to_sibling = parent;
            let mut sibling = mounts[parent].first_child;
            let mut change = FillSibling::FistChild;
            while let Some(sibling_) = sibling {
                /* If this mountpoint is a path prefix of the sibling,
                 * say this->mp=/foo/bar and sibling->mp=/foo, then it is
                 * covered by the sibling, and we drop it. */
                if has_path_prefix(&mounts[this].mountpoint, &mounts[sibling_].mountpoint) {
                    covered = true;
                    break;
                }

                /* If the sibling is a path prefix of this mount point,
                 * say this->mp=/foo and sibling->mp=/foo/bar, then the sibling
                 * is covered, and we drop it. */
                if has_path_prefix(&mounts[sibling_].mountpoint, &mounts[this].mountpoint) {
                    mounts[to_sibling].next_sibling = mounts[sibling_].next_sibling;
                } else {
                    change = FillSibling::NextSibling;
                    to_sibling = sibling_;
                }
                sibling = mounts[sibling_].next_sibling;
            }
            if covered {
                continue;
            }
            match change {
                FillSibling::FistChild => mounts[to_sibling].first_child = Some(this),
                FillSibling::NextSibling => mounts[to_sibling].next_sibling = Some(this),
            }
        }
        let mut out = Vec::new();
        collect_mounts(&mut out, &mounts, root);

        out.into_boxed_slice()
    }

    parse_mountinfo_inner(proc_fd, root_mount.as_ref())
}
