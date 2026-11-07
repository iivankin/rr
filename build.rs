fn main() {
    // Don't rebuild even if nothing changed
    println!("cargo:rerun-if-changed=build.rs");
    rustc_tools_util::setup_version_info!();
    // rr sits in a toolchain's bin/, as clippy-driver does, and loads the
    // compiler, librustc_driver, from the toolchain's lib/. On Windows the
    // compiler's DLLs are in bin/ beside it.
    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => println!("cargo:rustc-link-arg-bin=rr=-Wl,-rpath,@loader_path/../lib"),
        Ok("linux") => println!("cargo:rustc-link-arg-bin=rr=-Wl,-rpath,$ORIGIN/../lib"),
        _ => {},
    }
}
