#![allow(mutable_transmutes)]
#![allow(unused_assignments)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(static_mut_refs)]
#![allow(clippy::all)]
#![allow(useless_ptr_null_checks)]

extern crate libc;

pub mod bind_mount;
pub mod bubblewrap;
pub mod network;
pub mod parse_mountinfo;
pub mod privilged_op;
pub mod setup_newroot;
pub mod types;
pub mod utils;

mod serde_errno;

#[macro_use]
pub mod _macros {
    extern "C" {
        pub fn __errno_location() -> *mut libc::c_int;
    }
    #[macro_export]
    macro_rules! errno {
        () => {
            *$crate::_macros::__errno_location()
        };
    }

    #[macro_export]
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

    #[macro_export]
    macro_rules! OsString {
        ($ptr:expr) => {{
            assert!(!$ptr.is_null());
            ::std::ffi::OsStr::to_os_string(::std::ffi::OsStr::from_bytes(
                ::std::ffi::CStr::to_bytes(::std::ffi::CStr::from_ptr($ptr)),
            ))
        }};
    }
}

pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(bubblewrap::main_0(
            (args.len() - 1) as libc::c_int,
            args.as_mut_ptr() as *mut *mut libc::c_char,
        ) as i32)
    }
}
