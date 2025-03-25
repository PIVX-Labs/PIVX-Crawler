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

    let webhook = Webhook::new("https://discord.com/api/webhooks/1352221072208166952/W_TaVpQ2jxYD9s63YBHo0S-vkCnf7SVvzvYWU8OcEZb5tANHm7IecFTNRlu9TnAtG0-u");
    // Check peers found for hashes and compare for potential forks
    check_and_alert_forks(&peers, &webhook).await?;
    Ok(())
}
