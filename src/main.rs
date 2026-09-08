mod message;
mod node;
mod utils;
mod webhook;

use node::{Ip, Node, check_and_alert_forks};
use std::error::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use webhook::Webhook;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let node = Node {
        ip: Ip::Ip4("194.195.87.248".to_string()),
    };
    let peers = node.get_peers().await?;

    // A Discord webhook URL is a bearer credential: anyone holding it can post as the bot.
    // It was hardcoded here; keep it out of the repo.
    let webhook = Webhook::new(&std::env::var("CRAWLER_DISCORD_WEBHOOK")?);
    // Detect groupings where there's a large enough gap
    check_and_alert_forks(&peers, &webhook).await?;
    Ok(())
}
