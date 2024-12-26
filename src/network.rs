use crate::types::*;
use crate::*;
use ::libc;

use std::os::fd::RawFd;
use std::ptr::addr_of_mut;

unsafe fn add_rta(header: *mut nlmsghdr, rta_type: libc::c_int, size: usize) -> *mut libc::c_void {
    let rta_size = ((size_of::<rtattr>()) + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO + size - 1);

    let rta = (header as *mut libc::c_char)
        .add(((*header).nlmsg_len as usize + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1))
        as *mut rtattr;

    (*rta).rta_type = rta_type as _;
    (*rta).rta_len = rta_size as _;
    (*header).nlmsg_len = (((*header).nlmsg_len as usize + NLMSG_ALIGNTO - 1)
        & !(NLMSG_ALIGNTO - 1 + rta_size)) as u32;

    return (rta as *mut libc::c_char)
        .add((size_of::<rtattr>() + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1))
        as *mut libc::c_void;
}

unsafe fn rtnl_send_request(rtnl_fd: std::os::fd::RawFd, header: *mut nlmsghdr) -> libc::c_int {
    let mut dst_addr: MaybeUninit<sockaddr_nl> = MaybeUninit::zeroed();
    *addr_of_mut!((*dst_addr.as_mut_ptr()).nl_family) = libc::AF_NETLINK as _;
    let mut sent: ssize_t = 0;
    sent = retry!(sendto(
        rtnl_fd,
        header as *mut libc::c_void,
        (*header).nlmsg_len as size_t,
        0,
        dst_addr.as_ptr() as *mut sockaddr,
        ::core::mem::size_of::<sockaddr_nl>() as socklen_t,
    ));
    if sent < 0 {
        return -1;
    }
    return 0;
}

unsafe fn rtnl_read_reply(rtnl_fd: std::os::fd::RawFd, seq_nr: libc::c_uint) -> libc::c_int {
    let mut buffer: [libc::c_char; 1024] = [0; 1024];
    let mut received: ssize_t = 0;
    let mut rheader = 0 as *mut nlmsghdr;
    loop {
        received = retry!(recv(
            rtnl_fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            size_of::<[libc::c_char; 1024]>(),
            0,
        ));
        if received < 0 {
            return -1;
        }
        let mut received = received as usize;
        rheader = buffer.as_mut_ptr() as *mut nlmsghdr;
        while received >= NLMSG_HDRLEN as usize {
            if (*rheader).nlmsg_seq != seq_nr {
                return -1;
            }
            if (*rheader).nlmsg_pid as pid_t != getpid() {
                return -1;
            }
            if (*rheader).nlmsg_type as libc::c_int == libc::NLMSG_ERROR {
                let err = (rheader as *mut libc::c_char).offset(NLMSG_HDRLEN as _)
                    as *mut libc::c_void as *mut u32;
                if *err == 0 {
                    return 0;
                }
                return -1;
            }
            if (*rheader).nlmsg_type as libc::c_int == libc::NLMSG_DONE {
                return 0;
            }
            received -= ((*rheader).nlmsg_len as usize + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1);
            rheader = (rheader as *mut libc::c_char)
                .add(((*rheader).nlmsg_len as usize + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1))
                as *mut nlmsghdr;
        }
    }
}

unsafe fn rtnl_do_request(rtnl_fd: RawFd, header: *mut nlmsghdr) -> libc::c_int {
    if rtnl_send_request(rtnl_fd, header) != 0 {
        return -1;
    }
    if rtnl_read_reply(rtnl_fd, (*header).nlmsg_seq) != 0 {
        return -1;
    }
    return 0;
}

unsafe fn rtnl_setup_request(
    buffer: *mut libc::c_char,
    req_type: libc::c_int,
    flags: libc::c_int,
    size: size_t,
) -> *mut nlmsghdr {
    let len = size + NLMSG_HDRLEN as usize;
    static mut counter: u32 = 0;
    memset(buffer as *mut libc::c_void, 0, len);
    let header = buffer as *mut nlmsghdr;
    (*header).nlmsg_len = len as u32;
    (*header).nlmsg_type = req_type as _;
    (*header).nlmsg_flags = (flags | libc::NLM_F_REQUEST) as u16;
    (*header).nlmsg_seq = counter;
    (*header).nlmsg_pid = getpid() as u32;

    counter += 1;
    return header;
}

pub unsafe fn loopback_setup() {
    let mut r: libc::c_int = 0;
    let mut if_loopback: libc::c_int = 0;
    let mut rtnl_fd = -1;
    let mut buffer: [libc::c_char; 1024] = [0; 1024];
    let mut src_addr: MaybeUninit<sockaddr_nl> = MaybeUninit::zeroed();
    *addr_of_mut!((*src_addr.as_mut_ptr()).nl_family) = libc::AF_NETLINK as _;

    let mut header = std::ptr::null_mut() as *mut nlmsghdr;
    let mut addmsg = std::ptr::null_mut() as *mut ifaddrmsg;
    let mut infomsg = std::ptr::null_mut() as *mut ifinfomsg;
    let mut ip_addr = std::ptr::null_mut() as *mut in_addr;
    *addr_of_mut!((*src_addr.as_mut_ptr()).nl_pid) = getpid() as _;

    if_loopback = if_nametoindex(c"lo".as_ptr()) as libc::c_int;
    if if_loopback <= 0 {
        die_with_error!(c"loopback: Failed to look up lo".as_ptr());
    }
    rtnl_fd = socket(
        libc::PF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
        libc::NETLINK_ROUTE,
    );
    if rtnl_fd < 0 {
        die_with_error!(c"loopback: Failed to create NETLINK_ROUTE socket".as_ptr());
    }
    r = bind(
        rtnl_fd,
        src_addr.as_mut_ptr() as *mut sockaddr,
        size_of::<sockaddr_nl>() as socklen_t,
    );
    if r < 0 {
        die_with_error!(c"loopback: Failed to bind NETLINK_ROUTE socket".as_ptr(),);
    }

    header = rtnl_setup_request(
        buffer.as_mut_ptr(),
        libc::RTM_NEWADDR as _,
        libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
        size_of::<ifaddrmsg>(),
    );
    addmsg = (header as *mut libc::c_char).offset(NLMSG_HDRLEN as isize) as *mut ifaddrmsg;
    (*addmsg).ifa_family = libc::AF_INET as u8;
    (*addmsg).ifa_prefixlen = 8;
    (*addmsg).ifa_flags = libc::IFA_F_PERMANENT as u8;
    (*addmsg).ifa_scope = libc::RT_SCOPE_HOST as libc::c_int as u8;
    (*addmsg).ifa_index = if_loopback as u32;

    ip_addr = add_rta(header, libc::IFA_LOCAL as libc::c_int, size_of::<in_addr>()) as *mut in_addr;
    (*ip_addr).s_addr = htonl(libc::INADDR_LOOPBACK);

    ip_addr = add_rta(
        header,
        libc::IFA_ADDRESS as libc::c_int,
        size_of::<in_addr>(),
    ) as *mut in_addr;
    (*ip_addr).s_addr = htonl(libc::INADDR_LOOPBACK as in_addr_t);

    assert!(((*header).nlmsg_len as usize) < size_of::<[libc::c_char; 1024]>());
    if rtnl_do_request(rtnl_fd, header) != 0 {
        die_with_error!(c"loopback: Failed RTM_NEWADDR".as_ptr());
    }
    header = rtnl_setup_request(
        buffer.as_mut_ptr(),
        libc::RTM_NEWLINK as _,
        libc::NLM_F_ACK,
        size_of::<ifinfomsg>(),
    );

    infomsg = (header as *mut libc::c_char).add(NLMSG_HDRLEN as _) as *mut ifinfomsg;
    (*infomsg).ifi_family = libc::AF_UNSPEC as _;
    (*infomsg).ifi_type = 0;
    (*infomsg).ifi_index = if_loopback;
    (*infomsg).ifi_flags = libc::IFF_UP as _;
    (*infomsg).ifi_change = libc::IFF_UP as _;

    assert!(((*header).nlmsg_len as usize) < size_of::<[libc::c_char; 1024]>());

    if rtnl_do_request(rtnl_fd, header) != 0 {
        die_with_error!(c"loopback: Failed RTM_NEWLINK".as_ptr());
    }
}
