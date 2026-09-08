mod message;
mod node;
mod utils;
mod webhook;

use node::{Ip, Node, check_and_alert_forks};
use std::collections::HashMap;
use std::error::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use webhook::Webhook;

// Usage: pivx-crawler [--testnet] [--magic=<hex>] [--walk[=max]] [--depth=N] [--explorer=<url>] [seed]
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
    if let Some(url) = args.iter().find_map(|a| a.strip_prefix("--explorer=")) {
        net.explorer = Box::leak(url.to_string().into_boxed_str());
    }
    message::set_network(net);
    // 194.195.87.248 no longer answers. A dead seed yields an empty result, not an
    // error, so pass a live one as the first non-flag argument.
    let seed = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "194.195.87.248".to_string());

    // One node reports its own address book. Walking reaches the rest of the network,
    // which is what makes a family census a measurement rather than one peer's view.
    if let Some(flag) = args.iter().find(|a| a.starts_with("--walk")) {
        let max_peers = flag
            .strip_prefix("--walk=")
            .and_then(|v| v.parse().ok())
            .unwrap_or(500);
        let max_depth = args
            .iter()
            .find_map(|a| a.strip_prefix("--depth="))
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);

        let found = Node::recursive_discover_peers(Ip::Ip4(seed), max_peers, max_depth).await?;
        let mut by_family: HashMap<&str, usize> = HashMap::new();
        for ip in &found {
            *by_family.entry(ip.family()).or_default() += 1;
        }
        println!("walked {} peers, by family: {:?}", found.len(), by_family);
        return Ok(());
    }

    let node = Node { ip: Ip::Ip4(seed) };
    let (_addresses, peers) = node.get_peers().await?;

    let webhook = Webhook::new(&std::env::var("CRAWLER_DISCORD_WEBHOOK")?);
    check_and_alert_forks(&peers, &webhook).await?;
    Ok(())
}
