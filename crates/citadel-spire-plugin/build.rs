//! Compile the vendored upstream SPIRE plugin-SDK protos with a hermetic protoc,
//! and emit a file-descriptor set so the plugin can serve gRPC reflection (SPIRE
//! uses reflection to discover a plugin's services).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(out.join("citadel_spire_descriptor.bin"))
        .compile_protos(
            &[
                "proto/spire/plugin/server/nodeattestor/v1/nodeattestor.proto",
                "proto/spire/service/common/config/v1/config.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
