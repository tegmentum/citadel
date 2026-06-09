//! Compile the vendored upstream SPIRE plugin-SDK protos with a hermetic protoc
//! (no system protoc needed), so the crate builds anywhere CI runs.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(
            &[
                "proto/spire/plugin/server/nodeattestor/v1/nodeattestor.proto",
                "proto/spire/service/common/config/v1/config.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
