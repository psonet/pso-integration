fn main() {
    // Platform-specific configuration for cross-compilation

    #[cfg(target_os = "macos")]
    {
        // macOS specific settings
        println!("cargo:rustc-link-arg=-mmacosx-version-min=10.13");
    }

    #[cfg(target_os = "linux")]
    {
        // Linux specific settings (if needed)
    }

    // Set library search path (can be extended if needed)
    println!("cargo:rustc-link-search=native=/usr/lib");
}
