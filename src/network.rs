use ::libc::nlmsghdr;
use nix::sys::socket::{AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType};

use std::os::fd::{AsRawFd, RawFd};

use crate::utils::nix_retry;

#[repr(C)]
#[derive(Debug)]
struct ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8, /* The prefix length		*/
    ifa_flags: u8,     /* Flags			*/
    ifa_scope: u8,     /* Address scope		*/
    ifa_index: u32,    /* Link index			*/
}

#[repr(C)]
#[derive(Debug)]
struct rtattr {
    rta_len: u16,
    rta_type: u16,
}

#[repr(C)]
#[derive(Debug)]
pub struct ifinfomsg {
    ifi_family: u8,
    __ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

const RTA_ALIGNTO: usize = 4;
const NLMSG_ALIGNTO: usize = 4;
const NLMSG_HDRLEN: usize = nlmsg_align(size_of::<libc::nlmsghdr>());

// ((len) = NLMSG_ALIGN((nlh)->nlmsg_len),                                     \
const fn nlmsg_msglen(msg: &libc::nlmsghdr) -> usize {
    nlmsg_align(msg.nlmsg_len as usize)
}
const fn nlmsg_length(val: usize) -> usize {
    val + NLMSG_HDRLEN
}

const fn nlmsg_align(val: usize) -> usize {
    (val + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

//((void *)(((char *)nlh) + NLMSG_HDRLEN))
const fn nlmsg_data(msg: *const nlmsghdr) -> *const () {
    msg.cast::<u8>().wrapping_add(NLMSG_HDRLEN).cast()
}

//((void *)(((char *)nlh) + NLMSG_HDRLEN))
const fn nlmsg_data_mut(msg: *mut nlmsghdr) -> *mut () {
    msg.cast::<u8>().wrapping_add(NLMSG_HDRLEN).cast()
}

const fn rta_align(val: usize) -> usize {
    (val + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}
const fn rta_length(val: usize) -> usize {
    rta_align(size_of::<rtattr>()) + val
}
const fn rta_data(rta: *mut rtattr) -> *mut () {
    rta.cast::<u8>().wrapping_add(rta_length(0)).cast()
}

fn add_rta(header: &mut nlmsghdr, rta_type: libc::c_int, size: usize) -> *mut () {
    let rta_size = rta_length(size);

    let rta = unsafe {
        &mut *((&raw mut *header).cast::<u8>())
            .add(nlmsg_align((*header).nlmsg_len as _))
            .cast::<rtattr>()
    };

    rta.rta_type = rta_type as _;
    rta.rta_len = rta_size as _;
    header.nlmsg_len = (nlmsg_align(header.nlmsg_len as _) + rta_size) as _;

    return rta_data(rta);
}

fn counter() -> u32 {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

#[derive(Debug)]
pub enum LoopbackSetupError {
    NixError(nix::errno::Errno),
    GetInterface(nix::errno::Errno),
    CreateSocket(nix::errno::Errno),
    BindError(nix::errno::Errno),
    OutOfSequence,
    WrongPid,
    MsgError,
}

impl From<nix::errno::Errno> for LoopbackSetupError {
    fn from(value: nix::errno::Errno) -> Self {
        Self::NixError(value)
    }
}

const BUFFER_CAPACITY: usize = std::mem::size_of::<nlmsghdr>() * 64;
fn do_request(sock: RawFd, buffer: &mut [u8]) -> Result<(), LoopbackSetupError> {
    let header = unsafe { &*buffer.as_ptr().cast::<nlmsghdr>() };
    let dst_addr = nix::sys::socket::NetlinkAddr::new(0, 0);
    nix_retry!(nix::sys::socket::sendto(
        sock.as_raw_fd(),
        &buffer[..header.nlmsg_len as _],
        &dst_addr,
        MsgFlags::empty(),
    ))?;

    buffer.fill(0);

    let aligned_start = {
        let mut off = 0;
        while !(&raw const buffer[0]).cast::<nlmsghdr>().is_aligned() {
            off += 1;
        }
        off
    };
    assert!(aligned_start == 0);
    // shadowing the buffer binding so it will ALLWAYS be aligned (at list buffer[0]) correctly
    let buffer = &mut buffer[aligned_start..];
    assert!((&raw const buffer[0]).cast::<nlmsghdr>().is_aligned());
    loop {
        let received = nix_retry!(nix::sys::socket::recv(
            sock.as_raw_fd(),
            &mut buffer[aligned_start..],
            MsgFlags::empty()
        ))?;

        let mut data = &buffer[..received as usize];
        while data.len() >= NLMSG_HDRLEN {
            // SAFETY: this transmute is fine since data is at least `size_of::<nlmsghdr>()`
            //         We also made sure to align the vector to the correct alignment so the fist
            //         byte is aligned properly.
            //         There is no invalid bit pattern in this struct meaning that any *aligned*
            //         and *rightly sized* buffer is a reference worthy
            assert!((&raw const data[0]).cast::<nlmsghdr>().is_aligned());
            let rmsg: &nlmsghdr = unsafe { &*(&raw const data[0]).cast() };
            if rmsg.nlmsg_seq != header.nlmsg_seq {
                return Err(LoopbackSetupError::OutOfSequence);
            }
            if rmsg.nlmsg_pid != nix::unistd::getpid().as_raw() as _ {
                return Err(LoopbackSetupError::WrongPid);
            }
            if rmsg.nlmsg_type as libc::c_int == libc::NLMSG_ERROR {
                let err: *const u32 = nlmsg_data(rmsg).cast();
                // SAFETY: We just got a raw pointer because there is some unknown type after the
                // header. Here the message type dictates the payload type. We know that in case
                // we are here it'll be an an valid u32
                if unsafe { *err } == 0 {
                    return Ok(());
                }
                println!(
                    "err [raw={}] = {}",
                    unsafe { std::mem::transmute::<_, i32>(*err) },
                    nix::errno::Errno::from_raw(unsafe { *err } as _)
                );
                return Err(LoopbackSetupError::MsgError);
            }
            if rmsg.nlmsg_type as libc::c_int == libc::NLMSG_DONE {
                return Ok(());
            }

            data = &data[nlmsg_msglen(rmsg).min(data.len())..];
        }
    }
}

#[repr(C)]
struct AlignedTo<T> {
    _align: [T; 0],
    buffer: [u8; BUFFER_CAPACITY],
}

const _: () =
    assert!(std::mem::align_of::<AlignedTo<nlmsghdr>>() == std::mem::align_of::<nlmsghdr>());

pub fn loopback_setup() -> Result<(), LoopbackSetupError> {
    let mut buffer: AlignedTo<nlmsghdr> = AlignedTo {
        _align: [],
        buffer: [0; BUFFER_CAPACITY],
    };
    let buffer = &mut buffer.buffer;

    let src_addr: NetlinkAddr = NetlinkAddr::new(nix::unistd::getpid().as_raw() as _, 0);

    let if_loopback =
        nix::net::if_::if_nametoindex("lo").map_err(LoopbackSetupError::GetInterface)?;

    let rtnl_fd = nix::sys::socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        Some(SockProtocol::NetlinkRoute),
    )
    .map_err(LoopbackSetupError::CreateSocket)?;

    nix::sys::socket::bind(rtnl_fd.as_raw_fd(), &src_addr)
        .map_err(LoopbackSetupError::BindError)?;

    unsafe {
        (&raw mut buffer[0]).cast::<nlmsghdr>().write(nlmsghdr {
            nlmsg_len: nlmsg_length(size_of::<ifaddrmsg>()) as _,
            nlmsg_type: libc::RTM_NEWADDR as _,
            nlmsg_flags: (libc::NLM_F_CREATE
                | libc::NLM_F_EXCL
                | libc::NLM_F_ACK
                | libc::NLM_F_REQUEST) as _,
            nlmsg_seq: counter(),
            nlmsg_pid: nix::unistd::getpid().as_raw() as _,
        })
    };
    unsafe {
        nlmsg_data((&raw const buffer[0]).cast())
            .cast::<ifaddrmsg>()
            .cast_mut()
            .write_unaligned(ifaddrmsg {
                ifa_family: libc::AF_INET as _,
                ifa_prefixlen: 8,
                ifa_flags: libc::IFA_F_PERMANENT as _,
                ifa_scope: libc::RT_SCOPE_HOST,
                ifa_index: if_loopback,
            });
    };

    unsafe {
        add_rta(
            &mut *(&raw mut buffer[0]).cast::<nlmsghdr>(),
            libc::IFA_LOCAL.into(),
            std::mem::size_of::<u32>(),
        )
        .cast::<u32>()
        .write_unaligned(if_loopback.to_be())
    };
    unsafe {
        add_rta(
            &mut *(&raw mut buffer[0]).cast::<nlmsghdr>(),
            libc::IFA_ADDRESS.into(),
            std::mem::size_of::<u32>(),
        )
        .cast::<u32>()
        .write_unaligned(if_loopback.to_be())
    };

    do_request(rtnl_fd.as_raw_fd(), buffer)?;
    buffer.fill(0);
    unsafe {
        (&raw mut buffer[0]).cast::<nlmsghdr>().write(nlmsghdr {
            nlmsg_len: nlmsg_length(size_of::<ifinfomsg>()) as _,
            nlmsg_type: libc::RTM_NEWLINK as _,
            nlmsg_flags: (libc::NLM_F_ACK | libc::NLM_F_REQUEST) as _,
            nlmsg_seq: counter(),
            nlmsg_pid: nix::unistd::getpid().as_raw() as _,
        })
    };
    unsafe {
        nlmsg_data((&raw const buffer[0]).cast())
            .cast::<ifinfomsg>()
            .cast_mut()
            .write_unaligned(ifinfomsg {
                ifi_family: libc::AF_UNSPEC as _,
                __ifi_pad: 0,
                ifi_type: 0,
                ifi_index: if_loopback as _,
                ifi_flags: libc::IFF_UP as _,
                ifi_change: libc::IFF_UP as _,
            });
    };

    do_request(rtnl_fd.as_raw_fd(), buffer)?;
    Ok(())
}
