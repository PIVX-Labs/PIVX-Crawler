use sha2::Digest;
use sha2::Sha256;
use std::error::Error;
use std::sync::OnceLock;

use tokio::io::AsyncWriteExt;

#[derive(Clone, Copy)]
pub struct Network {
    pub magic: u32,
    pub port: u16,
    /// Blockbook v2 compatible status endpoint. Fork detection needs a trusted tip, and
    /// a mainnet explorer cannot supply one for testnet.
    pub explorer: &'static str,
    /// Drop addresses older than this. getaddr samples addrman, whose timestamps age at
    /// the rate peers actually churn, so the useful window follows the network rather
    /// than the clock.
    pub addr_max_age: i64,
}

/// pchMessageStart and nDefaultPort from CMainParams, chainparams.cpp:318.
pub const MAINNET: Network = Network {
    magic: 0x90c4fde9,
    port: 51472,
    explorer: "https://explorer.pivx.org",
    addr_max_age: 3 * 24 * 60 * 60,
};

/// CTestNetParams, chainparams.cpp:464-467.
///
/// testnet6 changed this from testnet5's f5e6d5ca. A wrong magic is dropped by peers,
/// so it reads as an empty network rather than an error.
pub const TESTNET: Network = Network {
    magic: 0xf6e7d6cb,
    port: 51474,
    explorer: "https://testnet-explorer.liquid369.wtf",
    // testnet6 was at height 24,504 on 2026-09-08, 131 days after genesis: about 7.7
    // minutes a block against a 60s target. With that little churn on a fleet this size,
    // 3 days returned zero addresses from a node that had 33.
    addr_max_age: 30 * 24 * 60 * 60,
};

static NETWORK: OnceLock<Network> = OnceLock::new();

/// Set from argv before the first connection. Later calls are ignored.
pub fn set_network(net: Network) {
    let _ = NETWORK.set(net);
}

pub fn network() -> &'static Network {
    NETWORK.get().unwrap_or(&MAINNET)
}

pub struct Message;

impl Message {
    pub async fn fill<S: AsyncWriteExt + Unpin>(
        stream: &mut S,
        command: [u8; 12],
        payload: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        // HEADER
        stream.write_u32(network().magic).await?;
        stream.write(&command).await?;
        stream.write_u32_le(payload.len() as u32).await?;

        let hash1 = Sha256::digest(&payload);
        let hash2 = Sha256::digest(&hash1);
        let mut checksum = &hash2[..4];

        stream.write(&checksum).await?;
        // PAYLOAD
        stream.write(payload).await?;
        println!(
            "Sent command: {}",
            std::str::from_utf8(&command).unwrap_or("Invalid")
        );

        Ok(())
    }
}
