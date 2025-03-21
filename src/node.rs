use bytes::{BufMut, BytesMut};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::message::Message;
use crate::utils::read_varint;

fn ipv4_to_ipv6_mapped(ipv4: Ipv4Addr) -> Ipv6Addr {
    let octets = ipv4.octets();
    Ipv6Addr::new(
        0,
        0,
        0,
        0,
        0,
        0xFFFF,
        ((octets[0] as u16) << 8) | octets[1] as u16,
        ((octets[2] as u16) << 8) | octets[3] as u16,
    )
}

pub const VERSION: u32 = 209;
pub const PROTOCOL_VERSION: u32 = 70927;
// no capabilities
pub const NODE_CAPABILITIES: u64 = 0;
pub const USER_AGENT: &str = "/DUDDINOSCRAWLER:0.1/";
// Only get nodes that have sent a message in the `TIME_CUTOFF` seconds
pub const TIME_CUTOFF: i64 = 28800;

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum Ip {
    Ip4(String),
    Ip6(String),
    Onion(String),
}

impl AsRef<str> for Ip {
    fn as_ref(&self) -> &str {
        match self {
            Ip::Ip4(ip) => ip.as_ref(),
            Ip::Ip6(ip) => ip.as_ref(),
            Ip::Onion(ip) => ip.as_ref(),
        }
    }
}

pub struct Node {
    pub ip: Ip,
}

impl Node {
    pub async fn send_version(&self, stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        let mut payload = BytesMut::with_capacity(1000);

        payload.put_u32_le(PROTOCOL_VERSION);
        payload.put_u64_le(NODE_CAPABILITIES);
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        payload.put_u64_le(time);

        // addr_recv
        payload.put_u64_le(NODE_CAPABILITIES);
        let bits = match &self.ip {
            Ip::Ip4(ip) => ipv4_to_ipv6_mapped(Ipv4Addr::from_str(&ip)?).to_bits(),
            Ip::Ip6(ip) => Ipv6Addr::from_str(&ip)?.to_bits(),
            Ip::Onion(_) => todo!(),
        };
        payload.put_u128(bits);
        payload.put_u16(51472u16);
        // addr_from, not needed, sending 0

        payload.put_u64_le(NODE_CAPABILITIES);
        let tmp = stream.local_addr().unwrap().to_string();
        let ip = tmp.split(":").next().unwrap();
        let bits = match Ip::Ip4(ip.to_string()) {
            Ip::Ip4(ip) => ipv4_to_ipv6_mapped(Ipv4Addr::from_str(&ip)?).to_bits(),
            Ip::Ip6(ip) => Ipv6Addr::from_str(&ip)?.to_bits(),
            Ip::Onion(_) => todo!(),
        };
        payload.put_u128(bits);
        payload.put_u16(stream.local_addr()?.port());

        let nonce: u64 = rand::random();
        payload.put_u64_le(nonce);
        // user agent
        payload.put_u8(USER_AGENT.len() as u8);
        payload.put(USER_AGENT.as_bytes());
        // START HEIGHT
        payload.put_u32(0);
        // relay
        payload.put_u8(0);

        let command = b"version\0\0\0\0\0";
        Message::fill(stream, *command, &payload).await?;
        Ok(())
    }

    pub async fn send_verack(&self, stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        let command = b"verack\0\0\0\0\0\0";
        Message::fill(stream, *command, &[]).await?;
        Ok(())
    }

    pub async fn send_sendaddrv2(&self, stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        let command = b"sendaddrv2\0\0";
        Message::fill(stream, *command, &[]).await?;
        Ok(())
    }

    pub async fn send_getaddr(&self, stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        let command = b"getaddr\0\0\0\0\0";
        Message::fill(stream, *command, &[]).await?;
        Ok(())
    }

    pub async fn send_getblocks(&self, stream: &mut TcpStream, locators: &Vec<[u8; 32]>) -> Result<(), Box<dyn Error>> {
        let mut payload = BytesMut::with_capacity(81);
        payload.put_u32_le(PROTOCOL_VERSION);
        payload.put_u8(locators.len() as u8);
        for hash in locators {
            payload.extend_from_slice(hash);
        }
        payload.extend_from_slice(&[0u8; 32]);
        Message::fill(stream, *b"getblocks\0\0\0", &payload).await
    }

    pub async fn send_getdata(&self, stream: &mut TcpStream, block_hashes: &[[u8; 32]]) -> Result<(), Box<dyn Error>> {
        let mut payload = BytesMut::with_capacity(37 * block_hashes.len());
        payload.put_u8(block_hashes.len() as u8);
        for hash in block_hashes {
            // MSG_BLOCK to request full block data, 1 for TX
            payload.put_u32_le(2);
            payload.extend_from_slice(hash);
        }
        Message::fill(stream, *b"getdata\0\0\0\0\0", &payload).await
    }

    pub async fn receive_block(&self, stream: &mut TcpStream) -> Result<[u8; 32], Box<dyn Error>> {
        let payload = self.get_payload(stream, Some(*b"block\0\0\0\0\0\0\0")).await?;
        let mut cursor = Cursor::new(payload);
        let mut block_hash = [0u8; 32];
        cursor.read_exact(&mut block_hash).await?;
        Ok(block_hash)
    }

    pub async fn receive_inv(&self, stream: &mut TcpStream) -> Result<Vec<[u8; 32]>, Box<dyn Error>> {
        let payload = self.get_payload(stream, Some(*b"inv\0\0\0\0\0\0\0\0\0")).await?;
        let mut cursor = Cursor::new(payload);
        let count = read_varint(&mut cursor)?;
        let mut hashes = Vec::new();
        for _ in 0..count {
            let mut entry = [0u8; 36];
            cursor.read_exact(&mut entry).await?;
            if u32::from_le_bytes(entry[0..4].try_into()?) == 2 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&entry[4..]);
                hash.reverse();
                hashes.push(hash);
            }
        }
        Ok(hashes)
    }

    /**
     * if command is None, return the first message we receive
     * if it's Some(payload), discard all messages until we get the desired one
     */
    pub async fn get_payload(
        &self,
        stream: &mut TcpStream,
        command: Option<[u8; 12]>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        loop {
            // magic
            stream.read_u32().await?;
            // Command
            let mut received_command = [0u8; 12];
            stream.read(&mut received_command).await?;

            let length = stream.read_u32_le().await?;
            // checksum
            stream.read_u32_le().await?;
            let mut payload = vec![0u8; length as usize];
            stream.read(&mut payload).await?;

            if received_command == *b"ping\0\0\0\0\0\0\0\0" {
                // reply with pong
                Message::fill(stream, *b"pong\0\0\0\0\0\0\0\0", &payload).await?;
            }

            match command {
                Some(command) => {
                    if received_command == command {
                        println!(
                            "Received command: {}",
                            std::str::from_utf8(&received_command).unwrap_or("Invalid")
                        );

                        break Ok(payload);
                    }
                }
                None => {
                    println!(
                        "Received command: {}",
                        std::str::from_utf8(&received_command).unwrap_or("Invalid")
                    );
                    break Ok(payload);
                }
            }
        }
    }

    pub async fn get_block_height(&self, payload: &[u8]) -> Result<u32, Box<dyn Error>> {
        let mut payload = Cursor::new(payload);
        payload.read_exact(&mut [0u8; 80]).await?;
        let user_agent_len = read_varint(&mut payload)?;
        payload
            .read_exact(&mut vec![0u8; user_agent_len as usize])
            .await?;
        Ok(payload.read_u32_le().await?)
    }

    pub async fn get_peers(&self) -> Result<HashMap<Ip, u32>, Box<dyn Error>> {
        let mut stream = TcpStream::connect(format!("{}:51472", self.ip.as_ref())).await?;
        self.send_version(&mut stream).await?;
        // Discard version message, we really don't care
        let version_payload = self
            .get_payload(&mut stream, Some(*b"version\0\0\0\0\0"))
            .await?;
        println!(
            "Block height is: {}",
            self.get_block_height(&version_payload).await?
        );
        self.send_sendaddrv2(&mut stream).await?;
        self.send_verack(&mut stream).await?;
        // Discard verack message
        self.get_payload(&mut stream, Some(*b"verack\0\0\0\0\0\0"))
            .await?;

        let mut peers = HashMap::new();

        for i in 0..5 {
            self.send_getaddr(&mut stream).await?;
            self.send_getaddr(&mut stream).await?;
            let payload = self
                .get_payload(&mut stream, Some(*b"addrv2\0\0\0\0\0\0"))
                .await?;
            self.extract_ips(&payload, &mut peers).await?;
        }
        Ok(peers)
    }

    pub async fn extract_ips(
        &self,
        payload: &[u8],
        ips: &mut HashMap<Ip, u32>,
    ) -> Result<(), Box<dyn Error>> {
        let mut payload = Cursor::new(payload);
        let ip_length = read_varint(&mut payload)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        for i in 0..ip_length {
            let time = payload.read_u32_le().await?;

            // Services, don't care
            read_varint(&mut payload)?;
            let network_id = payload.read_u8().await?;

            match network_id {
                0x01 => {
                    let addr_len = read_varint(&mut payload)?;
                    if addr_len != 4 {
                        Err("Invalid ipv4 address")?;
                    }
                    let mut addr = vec![0u8; addr_len as usize];
                    payload.read(&mut addr).await?;
                    let port = payload.read_u16().await?;

                    // Only get nodes within TIME_CUTOFF, or we may get a bunch of garbage
                    if i64::abs((time as i64) - (now as i64)) <= TIME_CUTOFF {
                        ips.entry(Ip::Ip4(format!(
                            "{}.{}.{}.{}",
                            addr[0], addr[1], addr[2], addr[3]
                        )))
                        .and_modify(|i| *i = if time > *i { time } else { *i })
                        .or_insert(time);
                    }
                }
                // TODO: add other networks
                _ => {
                    let addr_len = read_varint(&mut payload)?;
                    let mut addr = vec![0u8; addr_len as usize];
                    payload.read(&mut addr).await?;
                    let port = payload.read_u16().await?;
                }
            }
        }
        Ok(())
    }
}
