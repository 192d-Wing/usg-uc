//! Build script for compiling protobuf definitions using tonic-prost-build.

use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "proto/config.proto",
        "proto/call.proto",
        "proto/registration.proto",
        "proto/health.proto",
        "proto/system.proto",
        "proto/cluster.proto",
    ];

    // Recompile if any proto file changes
    for proto in &protos {
        println!("cargo:rerun-if-changed={proto}");
    }

    // Get the output directory
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // Configure and build with file descriptor set for reflection
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // Generate file descriptor set for gRPC reflection
        .file_descriptor_set_path(out_dir.join("sbc_descriptor.bin"))
        .compile_protos(&protos, &["proto"])?;

    Ok(())
}
