mod message;
mod node;
mod utils;
mod webhook;

use node::{Ip, Node, check_and_alert_forks};
use std::error::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use webhook::Webhook;

// Usage: pivx-crawler [--testnet] [--magic=<hex>] [seed-address]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut net = if args.iter().any(|a| a == "--testnet") {
        message::TESTNET
    } else {
        message::MAINNET
    };
    if let Some(hex) = args.iter().find_map(|a| a.strip_prefix("--magic=")) {
        net.magic = u32::from_str_radix(hex, 16)?;
    }
    message::set_network(net);
    // 194.195.87.248 no longer answers. A dead seed yields an empty result, not an
    // error, so pass a live one as the first non-flag argument.
    let seed = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "194.195.87.248".to_string());

    let node = Node { ip: Ip::Ip4(seed) };
    let (_addresses, peers) = node.get_peers().await?;

    let webhook = Webhook::new(&std::env::var("CRAWLER_DISCORD_WEBHOOK")?);
    check_and_alert_forks(&peers, &webhook).await?;
    Ok(())
}
