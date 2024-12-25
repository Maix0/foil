#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![allow(clippy::all)]

extern crate libc;

pub mod bind_mount;
pub mod bubblewrap;
pub mod network;
pub mod types;
pub mod utils;

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
