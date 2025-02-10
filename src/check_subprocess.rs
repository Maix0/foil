use std::{
    ffi::{OsStr, OsString},
    mem::forget,
};

static WAS_HANDLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

const PROGRAM_NAME: &str = "/proc/self/exe/foil-subprocess";

pub fn handle_subproces() -> std::convert::Infallible {
    todo!()
}

pub fn check_subprocess() -> Result<Option<std::convert::Infallible>, std::convert::Infallible> {
    struct AbortOnPanic;
    impl Drop for AbortOnPanic {
        fn drop(&mut self) {
            panic!("panic to abort process");
        }
    }

    let bomb = AbortOnPanic;

    let Some(is_single_threaded) = num_threads::is_single_threaded() else {
        panic!("Couldn't get number of threads of program to assert that it is single threaded");
    };
    if !is_single_threaded {
        panic!(
            "Function called while not in a single thread program (or before spawning any threads)"
        );
    }

    if WAS_HANDLED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        panic!("Function was called multiple times");
    };

    let argv0 = std::env::args_os().next();
    if argv0.as_ref().map(OsString::as_os_str) == Some(OsStr::new(PROGRAM_NAME)) {
        forget(bomb);
        return Ok(Some(handle_subproces()));
    };
    forget(bomb);
    Ok(None)
}
