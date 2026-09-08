use bytes::{BufMut, BytesMut};
use std::collections::{HashMap, HashSet, VecDeque};
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
use crate::webhook::Webhook;

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

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
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

type BlockHash = [u8; 32];
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
        Message::fill(stream, *b"getaddr\0\0\0\0\0", &[]).await
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
            payload.put_u32_le(2); // MSG_BLOCK
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

    pub async fn get_payload(
        &self,
        stream: &mut TcpStream,
        command: Option<[u8; 12]>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        loop {
            match stream.read_u32().await {
                Ok(_) => {
                    let mut received_command = [0u8; 12];
                    stream.read(&mut received_command).await?;
                    let length = stream.read_u32_le().await?;
                    stream.read_u32_le().await?; // checksum
                    let mut payload = vec![0u8; length as usize];
                    stream.read(&mut payload).await?;

                    if received_command == *b"ping\0\0\0\0\0\0\0\0" {
                        Message::fill(stream, *b"pong\0\0\0\0\0\0\0\0", &payload).await?;
                        continue;
                    }

                    match command {
                        Some(expected) if received_command == expected => return Ok(payload),
                        None => return Ok(payload),
                        _ => continue,
                    }
                }
                Err(_) => return Err("Stream closed by peer".into()),
            }
        }
    }

    pub async fn get_block_height(&self, payload: &[u8]) -> Result<u32, Box<dyn Error>> {
        let mut payload = Cursor::new(payload);
        payload.read_exact(&mut [0u8; 80]).await?;
        let user_agent_len = read_varint(&mut payload)?;
        payload.read_exact(&mut vec![0u8; user_agent_len as usize]).await?;
        Ok(payload.read_u32_le().await?)
    }

    pub async fn extract_ips(
        &self,
        payload: &[u8],
        ips: &mut HashMap<Ip, u32>,
    ) -> Result<(), Box<dyn Error>> {
        let mut payload = Cursor::new(payload);
        let ip_length = read_varint(&mut payload)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        for _ in 0..ip_length {
            let time = payload.read_u32_le().await?;
            read_varint(&mut payload)?; // skip services
            let network_id = payload.read_u8().await?;

            if network_id == 0x01 {
                let addr_len = read_varint(&mut payload)?;
                if addr_len != 4 { continue; }
                let mut addr = vec![0u8; addr_len as usize];
                payload.read(&mut addr).await?;
                payload.read_u16().await?;

                if i64::abs((time as i64) - (now as i64)) <= TIME_CUTOFF {
                    ips.entry(Ip::Ip4(format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])))
                        .and_modify(|i| *i = (*i).max(time))
                        .or_insert(time);
                }
            } else {
                let addr_len = read_varint(&mut payload)?;
                let mut addr = vec![0u8; addr_len as usize];
                payload.read(&mut addr).await?;
                payload.read_u16().await?;
            }
        }

        Ok(())
    }

    pub async fn get_peers(&self) -> Result<HashMap<Ip, (u32, Vec<BlockHash>)>, Box<dyn Error>> {
        let mut stream = TcpStream::connect(format!("{}:51472", self.ip.as_ref())).await?;
    
        self.send_version(&mut stream).await?;
        let version_payload = self.get_payload(&mut stream, Some(*b"version\0\0\0\0\0")).await?;
        let peer_height = self.get_block_height(&version_payload).await?;
        println!("Connected peer's block height: {}", peer_height);
    
        self.send_verack(&mut stream).await?;
        self.get_payload(&mut stream, Some(*b"verack\0\0\0\0\0\0")).await?;
    
        self.send_sendaddrv2(&mut stream).await?;
    
        let mut peers = HashMap::new();
    
        // Get IP addresses of nodes peers
        for _ in 0..3 {
            self.send_getaddr(&mut stream).await?;
            if let Ok(payload) = self.get_payload(&mut stream, Some(*b"addrv2\0\0\0\0\0\0")).await {
                self.extract_ips(&payload, &mut peers).await?;
            } else {
                println!("Warning: Failed to receive addr response, continuing...");
                continue;
            }
        }
    
        // Check blockbook for latest data
        let best_block_hash = fetch_latest_block_hash_from_explorer().await?;
        // Map to store peer IPs with heights and recent hashes
        let mut peer_updates: HashMap<Ip, (u32, Vec<BlockHash>)> = HashMap::new();
        for peer_ip in peers.keys() {
            // Connect once per peer
            let Ok(mut peer_stream) = TcpStream::connect(format!("{}:51472", peer_ip.as_ref())).await else {
                println!("Failed to connect to peer {}", peer_ip.as_ref());
                continue;
            };
            if self.handshake_with_peer(&mut peer_stream).await.is_err() {
                println!("Handshake failed for peer {}", peer_ip.as_ref());
                continue;
            }
            if let Ok(peer_hashes) = self.fetch_recent_block_hashes(&mut peer_stream, best_block_hash, 10).await {
                peer_updates.insert(peer_ip.clone(), (peer_height, peer_hashes));
            }
        }        
        Ok(peer_updates)
    }
    
    // Simplified peer handshake setup
    pub async fn handshake_with_peer(&self, stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        self.send_version(stream).await?;
        self.get_payload(stream, Some(*b"version\0\0\0\0\0")).await?;
        self.send_verack(stream).await?;
        self.get_payload(stream, Some(*b"verack\0\0\0\0\0\0")).await?;
        Ok(())
    }

    pub async fn recursive_discover_peers(
        seed_ip: Ip,
        max_peers: usize,
        max_depth: usize,
    ) -> Result<HashSet<Ip>, Box<dyn Error>> {
        let mut seen_peers = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((seed_ip, 0));  // initial depth 0
    
        while let Some((current_ip, depth)) = queue.pop_front() {
            if seen_peers.len() >= max_peers || seen_peers.contains(&current_ip) {
                continue;
            }
    
            seen_peers.insert(current_ip.clone());
    
            println!(
                "Discovering peers from {} (depth: {}, total peers: {})",
                current_ip.as_ref(),
                depth,
                seen_peers.len()
            );
    
            if depth >= max_depth {
                continue;
            }
    
            let current_node = Node { ip: current_ip.clone() };
            match current_node.get_basic_peers().await {
                Ok(new_peers) => {
                    for new_ip in new_peers {
                        if !seen_peers.contains(&new_ip) {
                            queue.push_back((new_ip, depth + 1));
                        }
                    }
                }
                Err(e) => {
                    println!("Warning: Failed to get peers from {}: {:?}", current_ip.as_ref(), e);
                }
            }
        }
    
        Ok(seen_peers)
    }    

    /// Simple peer-discovery handshake (just enough to get IPs)
    pub async fn get_basic_peers(&self) -> Result<Vec<Ip>, Box<dyn Error>> {
        let mut stream = TcpStream::connect(format!("{}:51472", self.ip.as_ref())).await?;

        self.send_version(&mut stream).await?;
        self.get_payload(&mut stream, Some(*b"version\0\0\0\0\0")).await?;
        self.send_verack(&mut stream).await?;
        self.get_payload(&mut stream, Some(*b"verack\0\0\0\0\0\0")).await?;
        self.send_sendaddrv2(&mut stream).await?;
        self.send_getaddr(&mut stream).await?;

        let payload = self
            .get_payload(&mut stream, Some(*b"addrv2\0\0\0\0\0\0"))
            .await?;

        let mut peers = HashMap::new();
        self.extract_ips(&payload, &mut peers).await?;

        Ok(peers.into_keys().collect())
    }

    pub async fn fetch_recent_block_hashes(
        &self,
        stream: &mut TcpStream,
        locator: BlockHash,
        count: usize,
    ) -> Result<Vec<BlockHash>, Box<dyn Error>> {
        let mut hashes = Vec::new();
        let mut current_locator = vec![locator];
    
        while hashes.len() < count {
            self.send_getblocks(stream, &current_locator).await?;
            let new_hashes = self.receive_inv(stream).await?;
    
            if new_hashes.is_empty() {
                break;
            }
    
            hashes.extend(new_hashes.iter().take(count - hashes.len()));
    
            current_locator = vec![*new_hashes.last().unwrap()];
        }
    
        Ok(hashes)
    }        
}

/// Convert height/hash pair list to include dummy heights if missing.
pub fn normalize_peer_hashes(hashes: Vec<BlockHash>, height: u32) -> Vec<(u32, BlockHash)> {
    hashes.into_iter().enumerate().map(|(i, hash)| (height - i as u32, hash)).collect()
}

/// Group peers into forked chains based on shared block hashes and height proximity.
pub fn group_by_chain_similarity(peers: &HashMap<Ip, (u32, Vec<BlockHash>)>) -> Vec<Vec<Ip>> {
    let mut enriched: HashMap<Ip, (u32, Vec<(u32, BlockHash)>)> = peers.iter()
        .map(|(ip, (height, hashes))| (ip.clone(), (*height, normalize_peer_hashes(hashes.clone(), *height))))
        .collect();

    let mut groups: Vec<Vec<Ip>> = Vec::new();

    for (ip, (_, hashes)) in &enriched {
        let mut matched = false;

        for group in groups.iter_mut() {
            if let Some(first_ip) = group.first() {
                if let Some((_, base_hashes)) = enriched.get(first_ip) {
                    if hashes.iter().any(|(_, h)| base_hashes.iter().any(|(_, bh)| h == bh)) {
                        group.push(ip.clone());
                        matched = true;
                        break;
                    }
                }
            }
        }

        if !matched {
            groups.push(vec![ip.clone()]);
        }
    }

    groups
}

/// Find earliest common ancestor (block height + hash) among a group of peers.
pub fn find_common_ancestor(peers: &Vec<(Ip, Vec<(u32, BlockHash)>)>) -> Option<(u32, BlockHash)> {
    if peers.is_empty() {
        return None;
    }

    let first_hashes = &peers[0].1;
    for (h, hash) in first_hashes {
        if peers.iter().all(|(_, hashes)| hashes.iter().any(|(_, other)| other == hash)) {
            return Some((*h, *hash));
        }
    }
    None
}

/// Format fork alert message with chain group details.
pub fn format_fork_message(peers: &HashMap<Ip, (u32, Vec<BlockHash>)>, groups: &[Vec<Ip>]) -> String {
    let enriched: HashMap<Ip, (u32, Vec<(u32, BlockHash)>)> = peers.iter()
        .map(|(ip, (height, hashes))| (ip.clone(), (*height, normalize_peer_hashes(hashes.clone(), *height))))
        .collect();

    let mut msg = String::from("⚠️ **Forked Chain Groups Detected**\n\n");

    for (i, group) in groups.iter().enumerate() {
        msg += &format!("🔗 Group {}:\n", i + 1);

        let group_data: Vec<(Ip, Vec<(u32, BlockHash)>)> = group.iter()
            .filter_map(|ip| enriched.get(ip).map(|(_, hashes)| ((*ip).clone(), hashes.clone())))
            .collect();

        if let Some((ancestor_height, ancestor_hash)) = find_common_ancestor(&group_data) {
            msg += &format!("  ↪ Common Ancestor: Height `{}` | Hash `{}`\n\n", ancestor_height, hex::encode(ancestor_hash));
        }

        for ip in group {
            if let Some((height, hashes)) = enriched.get(ip) {
                let last_hash = hashes.last().map(|(_, h)| hex::encode(h)).unwrap_or_else(|| "N/A".to_string());
                msg += &format!("• {} → Height: `{}` | Hash: `{}`\n", ip.as_ref(), height, last_hash);
            }
        }

        msg += "\n";
    }

    msg
}

pub async fn check_and_alert_forks(
    peers: &HashMap<Ip, (u32, Vec<BlockHash>)>,
    webhook: &Webhook,
) -> Result<(), Box<dyn Error>> {
    let groups = group_peers_by_exact_hash(peers);
    if groups.len() > 1 {
        let msg = format_fork_message_by_hash(peers, &groups);
        webhook.send_embed("Blockchain Fork Detected", &msg, 0xFF0000).await?;
    }
    Ok(())
}

pub fn format_fork_message_by_hash(
    peers: &HashMap<Ip, (u32, Vec<BlockHash>)>,
    groups: &HashMap<BlockHash, Vec<Ip>>,
) -> String {
    let mut msg = String::from("⚠️ **Forked Chain Groups Detected**\n\n");

    for (hash, ips) in groups.iter() {
        let hash_display = if *hash == [0u8;32] { "N/A".to_string() } else { hex::encode(hash) };
        msg += &format!("🔗 Fork (Hash: `{}`):\n", hash_display);

        for ip in ips {
            if let Some((height, _)) = peers.get(ip) {
                msg += &format!("• {} → Height: `{}`\n", ip.as_ref(), height);
            }
        }

        msg += "\n";
    }

    msg
}

pub fn group_peers_by_exact_hash(peers: &HashMap<Ip, (u32, Vec<BlockHash>)>) -> HashMap<BlockHash, Vec<Ip>> {
    let mut groups: HashMap<BlockHash, Vec<Ip>> = HashMap::new();

    for (ip, (_height, hashes)) in peers {
        if let Some(last_hash) = hashes.first() {
            groups.entry(*last_hash).or_default().push(ip.clone());
        } else {
            groups.entry([0u8; 32]).or_default().push(ip.clone()); // special "N/A" or "unknown" group
        }
    }

    groups
}

pub async fn fetch_latest_block_hash_from_explorer() -> Result<[u8; 32], Box<dyn Error>> {
    let url = "https://explorer.duddino.com/api/status";
    let res = reqwest::get(url).await?.json::<serde_json::Value>().await?;

    if let Some(hash_hex) = res["backend"]["bestBlockHash"].as_str() {
        let mut hash = [0u8; 32];
        if let Ok(decoded) = hex::decode(hash_hex) {
            if decoded.len() == 32 {
                hash.copy_from_slice(&decoded);
                hash.reverse();
                return Ok(hash);
            }
        }
    }

    Err("Failed to retrieve or parse bestBlockHash".into())
}

pub async fn fetch_latest_block_height_from_explorer() -> Result<u32, Box<dyn Error>> {
    let url = "https://explorer.duddino.com/api/status";
    let res = reqwest::get(url).await?.json::<serde_json::Value>().await?;

    if let Some(height) = res["backend"]["blocks"].as_u64() {
        Ok(height as u32)
    } else {
        Err("Failed to fetch best height".into())
    }
}

pub fn detect_groupings(peers: &HashMap<Ip, u32>, gap_threshold: u32) -> Vec<Vec<(Ip, u32)>> {
    let mut heights: Vec<(Ip, u32)> = peers.iter().map(|(ip, &h)| (ip.clone(), h)).collect();
    heights.sort_by_key(|&(_, h)| h);
    let mut groups = vec![];
    let mut group = vec![];
    let mut prev = None;
    for (ip, h) in heights {
        if let Some(ph) = prev {
            if h.saturating_sub(ph) >= gap_threshold {
                groups.push(group);
                group = vec![];
            }
        }
        group.push((ip, h));
        prev = Some(h);
    }
    if !group.is_empty() {
        groups.push(group);
    }
    groups
}