//! Build script for compiling protobuf definitions using tonic-prost-build.

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

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&protos, &["proto"])?;

    Ok(())
}
