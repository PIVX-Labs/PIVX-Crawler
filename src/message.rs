use sha2::Digest;
use sha2::Sha256;
use std::error::Error;

use tokio::io::AsyncWriteExt;

pub const MAGIC: u32 = 0x90c4fde9;

pub struct Message;

impl Message {
    pub async fn fill<S: AsyncWriteExt + Unpin>(
        stream: &mut S,
        command: [u8; 12],
        payload: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        // HEADER
        stream.write_u32(MAGIC).await?;
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
