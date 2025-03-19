mod message;
mod node;
mod utils;

use node::{Ip, Node};
use std::error::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let node = Node {
        ip: Ip::Ip4("194.195.87.248".to_string()),
    };
    let peers = node.get_peers().await?;
    println!("found {:?}", peers);
    Ok(())
}
