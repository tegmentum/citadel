//! tpmd binary entry point. All server logic lives in [`tpmd::run`].

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tpmd::run().await
}
