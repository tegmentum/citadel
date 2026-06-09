//! Compile the vendored SPIRE server-API Entry protos (+ the google WKT) with a
//! hermetic protoc, into a single include file (handles the multi-package
//! cross-references for us).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .include_file("spire_api.rs")
        .compile_protos(
            &[
                "proto/spire/api/server/entry/v1/entry.proto",
                "proto/spire/api/types/entry.proto",
                "proto/spire/api/types/spiffeid.proto",
                "proto/spire/api/types/selector.proto",
                "proto/spire/api/types/federateswith.proto",
                "proto/spire/api/types/status.proto",
                "proto/google/protobuf/wrappers.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
