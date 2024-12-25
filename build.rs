#[cfg(all(unix, not(target_os = "macos")))]
fn main() {
    // add unix dependencies below
    println!("cargo:rustc-flags=-l cap");
    cc::Build::new().file("src/funcs.c").compile("example");
}

#[cfg(target_os = "macos")]
fn main() {
    // add macos dependencies below
    // println!("cargo:rustc-flags=-l edit");
}
