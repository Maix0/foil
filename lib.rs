#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![feature(c_variadic)]
#![feature(register_tool)]
#![register_tool(c2rust)]

extern crate libc;
pub mod src {
    pub mod bind_mount;
    pub mod bubblewrap;
    pub mod network;
    pub mod utils;
    pub mod types;
} // mod src
//
pub use src::types;

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
