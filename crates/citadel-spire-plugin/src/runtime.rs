//! Shared go-plugin runtime for the Citadel SPIRE plugins (server + agent): the
//! magic-cookie check, unix-socket serving, AutoMTLS, and the stdout handshake
//! line. Each binary builds its tonic `Router` (its services + health +
//! reflection) and hands it to [`run`].

use std::env;

use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::server::{Connected, Router};

use crate::{MAGIC_COOKIE_KEY, MAGIC_COOKIE_VALUE};

/// Pick the protocol version from the host's `PLUGIN_PROTOCOL_VERSIONS` list (the
/// SPIRE plugin SDK uses version 1).
fn negotiate_version() -> u32 {
    env::var("PLUGIN_PROTOCOL_VERSIONS")
        .ok()
        .and_then(|vs| {
            vs.split(',')
                .filter_map(|s| s.trim().parse::<u32>().ok())
                .max()
        })
        .unwrap_or(1)
}

/// Run `router` as a SPIRE external (go-plugin) plugin: verify the magic cookie,
/// serve on a unix socket (mTLS if the host enabled AutoMTLS, else plaintext),
/// and emit the go-plugin handshake line.
pub async fn run(router: Router) -> anyhow::Result<()> {
    if env::var(MAGIC_COOKIE_KEY).ok().as_deref() != Some(MAGIC_COOKIE_VALUE) {
        eprintln!(
            "This binary is a SPIRE plugin (go-plugin) and is not meant to be executed directly. \
             SPIRE launches it. See README.md."
        );
        std::process::exit(1);
    }
    let auto_mtls = env::var("PLUGIN_CLIENT_CERT").ok();
    let version = negotiate_version();
    let socket = env::temp_dir().join(format!("citadel-spire-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)?;

    let server_cert = match &auto_mtls {
        Some(ca) => Some(crate::mtls::build(ca)?),
        None => None,
    };

    // Handshake line: CoreProto|AppProto|network|address|protocol|serverCert
    let cert_field = server_cert
        .as_ref()
        .map(|s| crate::mtls::handshake_cert_field(&s.cert_der))
        .unwrap_or_default();
    println!("1|{version}|unix|{}|grpc|{cert_field}", socket.display());
    use std::io::Write;
    std::io::stdout().flush()?;

    match server_cert {
        Some(tls) => {
            let acceptor = tokio_rustls::TlsAcceptor::from(tls.config);
            let incoming = async_stream::stream! {
                loop {
                    match listener.accept().await {
                        Ok((sock, _)) => match acceptor.accept(sock).await {
                            Ok(s) => yield Ok::<_, std::io::Error>(TlsConn(s)),
                            Err(e) => eprintln!("citadel-spire-plugin: tls accept: {e}"),
                        },
                        Err(e) => yield Err(e),
                    }
                }
            };
            router.serve_with_incoming(incoming).await?;
        }
        None => {
            router
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await?;
        }
    }
    let _ = std::fs::remove_file(&socket);
    Ok(())
}

/// A TLS-terminated unix connection presented to tonic (AutoMTLS path).
pub struct TlsConn(pub tokio_rustls::server::TlsStream<tokio::net::UnixStream>);

impl Connected for TlsConn {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl tokio::io::AsyncRead for TlsConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TlsConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
