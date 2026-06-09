# citadel-spire-plugin

A SPIRE **NodeAttestor** plugin (server side) that makes SPIRE's SVID issuance
conditional on Citadel mesh trust. It wraps the SP1 decision core
(`citadel-spiffe`): on `Attest`, it returns the node's SPIFFE ID +
`citadel:` selectors only when the mesh currently classifies the node
**Verified**; otherwise it returns `PermissionDenied`, so SPIRE will not issue
(or, since `can_reattest = true`, renew) the agent's SVID. Identity becomes a
continuously-earned property.

## What's here

- **gRPC services** (`src/lib.rs`): the upstream SPIRE plugin-SDK `NodeAttestor`
  v1 + `Config` services (real protos vendored under `proto/`, compiled with a
  hermetic `protoc`). Wraps a `TrustView` (the control plane's `spiffe_node_view`).
- **go-plugin binary** (`src/main.rs`): the external-plugin entrypoint SPIRE
  launches — magic-cookie handshake, unix-socket gRPC (health `"plugin"` →
  SERVING, reflection, the services), and the stdout handshake line
  `1|1|unix|<sock>|grpc|`.
- **Tests**: a self-contained gRPC round-trip (`tests/round_trip.rs`) and a
  **go-plugin host emulation** (`tests/go_plugin_host.rs`) that launches the
  binary, parses the handshake, health-checks, `Configure`s, and `Attest`s —
  exactly what SPIRE's go-plugin client does — proving the external protocol
  without a live SPIRE.

## Running against a live SPIRE (Docker)

The official image is `ghcr.io/spiffe/spire-server`. `deploy/` has a `server.conf`
that loads this plugin (`NodeAttestor "citadel" { plugin_cmd = ... }`) and a
`docker-compose.yml`.

```sh
# 1. Build a Linux plugin binary for the container's arch (e.g. via cross or a
#    rust:1.x container), placing it at target/release/citadel-spire-plugin.
# 2. Validate the SPIRE config with the official image (verified: prints
#    "SPIRE server configuration file is valid."):
docker run --rm --entrypoint /opt/spire/bin/spire-server \
    -v "$PWD/deploy/server.conf:/c/server.conf:ro" \
    ghcr.io/spiffe/spire-server:1.9.6 validate -config /c/server.conf
# 3. Bring it up:
docker compose -f deploy/docker-compose.yml up
```

## AutoMTLS — done

SPIRE enables go-plugin AutoMTLS (it sets `PLUGIN_CLIENT_CERT`). The plugin
handles it (`src/mtls.rs`): it parses `PLUGIN_CLIENT_CERT` as the client CA,
generates an ephemeral server cert, serves mutual TLS (requiring + verifying the
client cert) on the project's rustls/aws-lc provider, and advertises the base64
(RawStdEncoding) DER leaf as the 6th handshake field. Proven end to end by
`tests/go_plugin_automtls.rs`, which emulates the go-plugin host: it presents a
client cert, reads the advertised server cert, connects over mTLS, and Attests.

## The attestation pair — both halves built

A SPIRE NodeAttestor is a *pair*. Both are here:

- **Server** (`src/main.rs`, `citadel-spire-plugin`): verifies the payload against
  mesh trust, returns the identity + selectors only when Verified.
- **Agent** (`src/bin/agent_plugin.rs`, `citadel-spire-agent-plugin`): emits this
  node's payload (`CITADEL_NODE_ID`). Config in `deploy/agent.conf`.

`tests/attestation_pair.rs` runs both: the agent emits the payload, the server
verifies it and issues `spiffe://citadel.local/node/<id>` for a Verified node.
With AutoMTLS + both plugins, only a live SPIRE server/agent deployment (the SP5
hardware demo) remains.

The trust source is a `TrustView`: a JSON file (`CITADEL_TRUST_FILE`) for
standalone/demo runs; production points it at the control plane.
