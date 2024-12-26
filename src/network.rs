use crate::types::*;
use crate::*;
use ::libc;

use std::ptr::addr_of_mut;

unsafe fn add_rta(
    mut header: *mut nlmsghdr,
    mut type_0: libc::c_int,
    mut size: size_t,
) -> *mut libc::c_void {
    let mut rta = 0 as *mut rtattr;
    let mut rta_size = (::core::mem::size_of::<rtattr>() as u32)
        .wrapping_add(RTA_ALIGNTO as u32)
        .wrapping_sub(1)
        & !RTA_ALIGNTO.wrapping_sub(1).wrapping_add(size as u32);
    rta = (header as *mut libc::c_char).offset(
        (((*header).nlmsg_len)
            .wrapping_add(NLMSG_ALIGNTO)
            .wrapping_sub(1 as libc::c_uint)
            & !NLMSG_ALIGNTO.wrapping_sub(1 as libc::c_uint)) as isize,
    ) as *mut rtattr;
    (*rta).rta_type = type_0 as u16;
    (*rta).rta_len = rta_size as libc::c_ushort;
    (*header).nlmsg_len = (((*header).nlmsg_len)
        .wrapping_add(NLMSG_ALIGNTO)
        .wrapping_sub(1)
        & !NLMSG_ALIGNTO.wrapping_sub(1))
    .wrapping_add(rta_size as u32);
    return (rta as *mut libc::c_char).offset(
        ((::core::mem::size_of::<rtattr>() as libc::c_ulong)
            .wrapping_add(RTA_ALIGNTO as libc::c_ulong)
            .wrapping_sub(1 as libc::c_ulong)
            & !RTA_ALIGNTO.wrapping_sub(1 as libc::c_uint) as libc::c_ulong)
            .wrapping_add(0 as libc::c_ulong) as isize,
    ) as *mut libc::c_void;
}

unsafe fn rtnl_send_request(mut rtnl_fd: libc::c_int, mut header: *mut nlmsghdr) -> libc::c_int {
    let mut dst_addr: MaybeUninit<sockaddr_nl> = MaybeUninit::zeroed();
    *addr_of_mut!((*dst_addr.as_mut_ptr()).nl_family) = libc::AF_NETLINK as _;
    let mut sent: ssize_t = 0;
    sent = {
        loop {
            let __result = sendto(
                rtnl_fd,
                header as *mut libc::c_void,
                (*header).nlmsg_len as size_t,
                0,
                dst_addr.as_ptr() as *mut sockaddr,
                ::core::mem::size_of::<sockaddr_nl>() as socklen_t,
            );
            if !(__result == -(1) && errno!() == libc::EINTR) {
                break __result;
            }
        }
    };
    if sent < 0 {
        return -(1);
    }
    return 0;
}

unsafe fn rtnl_read_reply(mut rtnl_fd: libc::c_int, mut seq_nr: libc::c_uint) -> libc::c_int {
    let mut buffer: [libc::c_char; 1024] = [0; 1024];
    let mut received: ssize_t = 0;
    let mut rheader = 0 as *mut nlmsghdr;
    loop {
        received = loop {
            let __result = recv(
                rtnl_fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                ::core::mem::size_of::<[libc::c_char; 1024]>(),
                0,
            );
            if !(__result == -(1) && errno!() == libc::EINTR) {
                break __result;
            }
        };
        if received < 0 {
            return -(1);
        }
        rheader = buffer.as_mut_ptr() as *mut nlmsghdr;
        while received >= NLMSG_HDRLEN as isize {
            if (*rheader).nlmsg_seq != seq_nr {
                return -(1);
            }
            if (*rheader).nlmsg_pid as pid_t != getpid() {
                return -(1);
            }
            if (*rheader).nlmsg_type as libc::c_int == libc::NLMSG_ERROR {
                let mut err = (rheader as *mut libc::c_char).offset(NLMSG_HDRLEN as _)
                    as *mut libc::c_void as *mut u32;
                if *err == 0 as libc::c_uint {
                    return 0;
                }
                return -(1);
            }
            if (*rheader).nlmsg_type as libc::c_int == libc::NLMSG_DONE {
                return 0;
            }
            received -= (((*rheader).nlmsg_len)
                .wrapping_add(NLMSG_ALIGNTO)
                .wrapping_sub(1)
                & !NLMSG_ALIGNTO.wrapping_sub(1)) as isize;
            rheader = (rheader as *mut libc::c_char).offset(
                (((*rheader).nlmsg_len)
                    .wrapping_add(NLMSG_ALIGNTO)
                    .wrapping_sub(1)
                    & !NLMSG_ALIGNTO.wrapping_sub(1)) as isize,
            ) as *mut nlmsghdr;
        }
    }
}

unsafe fn rtnl_do_request(mut rtnl_fd: libc::c_int, mut header: *mut nlmsghdr) -> libc::c_int {
    if rtnl_send_request(rtnl_fd, header) != 0 {
        return -(1);
    }
    if rtnl_read_reply(rtnl_fd, (*header).nlmsg_seq) != 0 {
        return -(1);
    }
    return 0;
}

unsafe fn rtnl_setup_request(
    mut buffer: *mut libc::c_char,
    mut type_0: libc::c_int,
    mut flags: libc::c_int,
    mut size: size_t,
) -> *mut nlmsghdr {
    let mut header = 0 as *mut nlmsghdr;
    let mut len = size.wrapping_add(NLMSG_HDRLEN as _);
    static mut counter: u32 = 0 as u32;
    memset(buffer as *mut libc::c_void, 0, len);
    header = buffer as *mut nlmsghdr;
    (*header).nlmsg_len = len as u32;
    (*header).nlmsg_type = type_0 as u16;
    (*header).nlmsg_flags = (flags | libc::NLM_F_REQUEST) as u16;
    let fresh0 = counter;
    counter = counter.wrapping_add(1);
    (*header).nlmsg_seq = fresh0;
    (*header).nlmsg_pid = getpid() as u32;
    return header;
}

pub unsafe fn loopback_setup() {
    let mut r: libc::c_int = 0;
    let mut if_loopback: libc::c_int = 0;
    let mut rtnl_fd = -(1);
    let mut buffer: [libc::c_char; 1024] = [0; 1024];
    let mut src_addr: MaybeUninit<sockaddr_nl> = MaybeUninit::zeroed();
    *addr_of_mut!((*src_addr.as_mut_ptr()).nl_family) = libc::AF_NETLINK as _;

    let mut header = std::ptr::null_mut() as *mut nlmsghdr;
    let mut addmsg = std::ptr::null_mut() as *mut ifaddrmsg;
    let mut infomsg = std::ptr::null_mut() as *mut ifinfomsg;
    let mut ip_addr = std::ptr::null_mut() as *mut in_addr;
    *addr_of_mut!((*src_addr.as_mut_ptr()).nl_pid) = getpid() as _;
    if_loopback = if_nametoindex(b"lo\0" as *const u8 as *const libc::c_char) as libc::c_int;
    if if_loopback <= 0 {
        die_with_error!(b"loopback: Failed to look up lo\0" as *const u8 as *const libc::c_char);
    }
    rtnl_fd = socket(
        libc::PF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
        libc::NETLINK_ROUTE,
    );
    if rtnl_fd < 0 {
        die_with_error!(
            b"loopback: Failed to create NETLINK_ROUTE socket\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = bind(
        rtnl_fd,
        src_addr.as_mut_ptr() as *mut sockaddr,
        ::core::mem::size_of::<sockaddr_nl>() as libc::c_ulong as socklen_t,
    );
    if r < 0 {
        die_with_error!(
            b"loopback: Failed to bind NETLINK_ROUTE socket\0" as *const u8 as *const libc::c_char,
        );
    }
    header = rtnl_setup_request(
        buffer.as_mut_ptr(),
        libc::RTM_NEWADDR as _,
        libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK,
        ::core::mem::size_of::<ifaddrmsg>(),
    );
    addmsg = (header as *mut libc::c_char).offset(NLMSG_HDRLEN as libc::c_int as isize)
        as *mut libc::c_void as *mut ifaddrmsg;
    (*addmsg).ifa_family = libc::AF_INET as u8;
    (*addmsg).ifa_prefixlen = 8 as u8;
    (*addmsg).ifa_flags = libc::IFA_F_PERMANENT as u8;
    (*addmsg).ifa_scope = libc::RT_SCOPE_HOST as libc::c_int as u8;
    (*addmsg).ifa_index = if_loopback as u32;
    ip_addr = add_rta(
        header,
        libc::IFA_LOCAL as libc::c_int,
        ::core::mem::size_of::<in_addr>(),
    ) as *mut in_addr;
    (*ip_addr).s_addr = htonl(libc::INADDR_LOOPBACK as in_addr_t);
    ip_addr = add_rta(
        header,
        libc::IFA_ADDRESS as libc::c_int,
        ::core::mem::size_of::<in_addr>(),
    ) as *mut in_addr;
    (*ip_addr).s_addr = htonl(libc::INADDR_LOOPBACK as in_addr_t);
    assert!(
        ((*header).nlmsg_len as libc::c_ulong)
            < ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong
    );
    if rtnl_do_request(rtnl_fd, header) != 0 {
        die_with_error!(b"loopback: Failed RTM_NEWADDR\0" as *const u8 as *const libc::c_char);
    }
    header = rtnl_setup_request(
        buffer.as_mut_ptr(),
        libc::RTM_NEWLINK as _,
        libc::NLM_F_ACK,
        ::core::mem::size_of::<ifinfomsg>(),
    );
    infomsg = (header as *mut libc::c_char).offset(NLMSG_HDRLEN as libc::c_int as isize)
        as *mut libc::c_void as *mut ifinfomsg;
    (*infomsg).ifi_family = libc::AF_UNSPEC as libc::c_uchar;
    (*infomsg).ifi_type = 0 as libc::c_ushort;
    (*infomsg).ifi_index = if_loopback;
    (*infomsg).ifi_flags = libc::IFF_UP as libc::c_uint;
    (*infomsg).ifi_change = libc::IFF_UP as libc::c_uint;
    assert!(
        ((*header).nlmsg_len as libc::c_ulong)
            < ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong
    );
    if rtnl_do_request(rtnl_fd, header) != 0 {
        die_with_error!(b"loopback: Failed RTM_NEWLINK\0" as *const u8 as *const libc::c_char);
    }
}
