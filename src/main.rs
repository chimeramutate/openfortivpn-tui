mod actions;
mod app;
mod config;
mod runtime;
mod ui;
mod vpn;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    runtime::run().await
}
