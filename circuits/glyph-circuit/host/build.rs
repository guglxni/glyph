//! Build script for glyph-circuit-host.
//!
//! When the `risc0` feature is enabled, this script compiles the guest circuit
//! into a RISC-V ELF binary and embeds it via risc0-build.
//!
//! ## Requirements
//! - `risc0-toolchain` must be installed: `rustup toolchain install risc0`
//! - Or use `cargo risczero install` from the risc0 cargo plugin
//!
//! ## Feature Flags
//! - Without any feature: GLYPH_CIRCUIT_ELF stays empty, generate_proof() errors
//! - With `risc0` feature: real ELF is embedded, generate_proof() works
//!
//! ## How to Build
//! ```bash
//! cargo build --manifest-path circuits/glyph-circuit/host/Cargo.toml \
//!     --features risc0
//! ```
//!
//! Or from workspace root (once the guest is added to workspace members):
//! ```bash
//! cargo build -p glyph-circuit-host --features risc0
//! ```

fn main() {
    #[cfg(feature = "risc0")]
    build_guest();
}

#[cfg(feature = "risc0")]
fn build_guest() {
    use std::collections::HashMap;

    // Discover and compile the guest ELF.
    // risc0_build::embed_methods() looks for packages with the `risc0-zkvm-guest` dependency.
    // It compiles them with the `riscv32im-risc0-zkvm-elf` target and embeds the binary.
    risc0_build::embed_methods_with_options(HashMap::from([(
        // The guest package name (must match Cargo.toml)
        "glyph-circuit-guest",
        risc0_build::GuestOptions {
            // Cargo features to enable in the guest build
            features: vec![],
            // Reproducible build via Docker is off by default; the toolchain
            // installed via `rzup install` is used directly. Operators can
            // override `RISC0_USE_DOCKER=1` for hermetic builds.
            use_docker: None,
        },
    )]));
}
