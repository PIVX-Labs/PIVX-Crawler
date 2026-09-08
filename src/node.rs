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

use sha3::{Digest, Sha3_256};

use crate::message::{network, Message};
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

pub const PROTOCOL_VERSION: u32 = 70927;
// no capabilities
pub const NODE_CAPABILITIES: u64 = 0;
pub const USER_AGENT: &str = "/DUDDINOSCRAWLER:0.1/";
// getaddr samples addrman, not recently seen peers, so a short window discards most of
// the reply: at 8h one mainnet node's 1000 addresses all fell out. Core does not
// age-filter what it receives; addrman keeps entries for ADDRMAN_HORIZON_DAYS of 30.
// 3 days counts what the network currently believes is live without accepting the
// month-old tail.
pub const TIME_CUTOFF: i64 = 3 * 24 * 60 * 60;

// BIP155 network ids and their fixed address lengths. A length disagreeing with the id
// is malformed; Core throws, this drops the entry.
const BIP155_IPV4: u8 = 0x01;
const BIP155_IPV6: u8 = 0x02;
const BIP155_TORV2: u8 = 0x03;
const BIP155_TORV3: u8 = 0x04;
const BIP155_I2P: u8 = 0x05;
const BIP155_CJDNS: u8 = 0x06;

// CNetAddr::MAX_ADDRV2_SIZE. Peer-supplied varint: uncapped it asks for 16 EiB.
const MAX_ADDRV2_SIZE: u64 = 512;

// TORV2_IN_IPV6_PREFIX, netaddress.h.
const TORV2_IN_IPV6_PREFIX: [u8; 6] = [0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43];

// MAX_PROTOCOL_MESSAGE_LENGTH, PIVX Core net.h:78.
const MAX_PROTOCOL_MESSAGE_LENGTH: usize = 2 * 1024 * 1024;

// Core defers its getaddr reply to the next address broadcast, PoissonNextSend over
// AVG_ADDRESS_BROADCAST_INTERVAL of 30s (net_processing.cpp:2430, validation.h:109).
// A wait shorter than the tail of that distribution reports an empty network.
const ADDR_WAIT: Duration = Duration::from_secs(90);

// MAX_SUBVERSION_LENGTH, PIVX Core.
const MAX_SUBVERSION_LENGTH: u64 = 256;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum Ip {
    Ip4(String),
    Ip6(String),
    Onion(String),
    I2p(String),
    Cjdns(String),
}

impl Ip {
    /// Onion, I2P and CJDNS need a proxy, SAM session or tunnel. Recorded anyway:
    /// counting a family and dialling it are separate.
    pub fn is_directly_dialable(&self) -> bool {
        matches!(self, Ip::Ip4(_) | Ip::Ip6(_))
    }

    pub fn family(&self) -> &'static str {
        match self {
            Ip::Ip4(_) => "ipv4",
            Ip::Ip6(_) => "ipv6",
            Ip::Onion(_) => "onion",
            Ip::I2p(_) => "i2p",
            Ip::Cjdns(_) => "cjdns",
        }
    }
}

impl AsRef<str> for Ip {
    fn as_ref(&self) -> &str {
        match self {
            Ip::Ip4(ip) => ip.as_ref(),
            Ip::Ip6(ip) => ip.as_ref(),
            Ip::Onion(ip) => ip.as_ref(),
            Ip::I2p(ip) => ip.as_ref(),
            Ip::Cjdns(ip) => ip.as_ref(),
        }
    }
}

/// RFC 4648 base32, lowercase, unpadded, as Tor and I2P print addresses.
fn base32_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u16, 0u8);
    for &byte in data {
        acc = (acc << 8) | byte as u16;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// base32(pubkey || sha3-256(".onion checksum" || pubkey || 0x03)[..2] || 0x03) + ".onion",
/// per rend-spec-v3 and CNetAddr::SetSpecial. Without the checksum the string will not
/// parse back into a CNetAddr.
fn onion_v3_address(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([0x03]);
    let checksum = hasher.finalize();

    let mut addr = [0u8; 35];
    addr[..32].copy_from_slice(pubkey);
    addr[32..34].copy_from_slice(&checksum[..2]);
    addr[34] = 0x03;
    format!("{}.onion", base32_lower(&addr))
}

/// None drops the entry: wrong length for the id, dead Tor v2, or an unknown id.
fn decode_bip155_addr(network_id: u8, addr: &[u8]) -> Option<Ip> {
    match (network_id, addr.len()) {
        (BIP155_IPV4, 4) => Some(Ip::Ip4(
            Ipv4Addr::from(<[u8; 4]>::try_from(addr).ok()?).to_string(),
        )),
        (BIP155_IPV6, 16) => {
            let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?);
            // Re-gossiping IPv4 as ::ffff:a.b.c.d would let a peer inflate the IPv6
            // count at will. Core rejects both prefixes here, netaddress.h:432.
            if v6.to_ipv4_mapped().is_some() || addr.starts_with(&TORV2_IN_IPV6_PREFIX) {
                return None;
            }
            Some(Ip::Ip6(v6.to_string()))
        }
        // Tor withdrew v2 in October 2021. Core still accepts the id, hence the arm.
        (BIP155_TORV2, 10) => None,
        (BIP155_TORV3, 32) => Some(Ip::Onion(onion_v3_address(&<[u8; 32]>::try_from(addr).ok()?))),
        (BIP155_I2P, 32) => Some(Ip::I2p(format!("{}.b32.i2p", base32_lower(addr)))),
        // fc00::/8 prints as IPv6 but needs a cjdns tunnel, so count it separately.
        (BIP155_CJDNS, 16) => Some(Ip::Cjdns(
            Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?).to_string(),
        )),
        _ => None,
    }
}

/// The legacy `version` net_addr is a bare 16-byte IPv6 slot with no network tag.
/// SerializeV1Array writes zeros for anything with no IPv6 form; inventing an encoding
/// would have the peer read the onion key back as a routable address.
fn addr_bits(ip: &Ip) -> Result<u128, Box<dyn Error>> {
    Ok(match ip {
        Ip::Ip4(ip) => ipv4_to_ipv6_mapped(Ipv4Addr::from_str(ip)?).to_bits(),
        Ip::Ip6(ip) => Ipv6Addr::from_str(ip)?.to_bits(),
        Ip::Onion(_) | Ip::I2p(_) | Ip::Cjdns(_) => 0,
    })
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
        payload.put_u128(addr_bits(&self.ip)?);
        payload.put_u16(network().port);

        // Was: split local_addr on ":" and parse the head as IPv4, which yields "[2001"
        // on an IPv6 socket and fails the handshake.
        payload.put_u64_le(NODE_CAPABILITIES);
        let local = stream.local_addr()?;
        payload.put_u128(match local.ip() {
            IpAddr::V4(ip) => ipv4_to_ipv6_mapped(ip).to_bits(),
            IpAddr::V6(ip) => ip.to_bits(),
        });
        payload.put_u16(local.port());

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
                Ok(magic) => {
                    // Was read and dropped, so --testnet only applied on transmit.
                    if magic != crate::message::network().magic {
                        Err(format!(
                            "wrong network magic {magic:#010x}, expected {:#010x}",
                            crate::message::network().magic
                        ))?;
                    }
                    let mut received_command = [0u8; 12];
                    stream.read_exact(&mut received_command).await?;
                    let length = stream.read_u32_le().await?;
                    // Peer-supplied and 32 bits wide: unchecked it asks for 4 GiB.
                    if length as usize > MAX_PROTOCOL_MESSAGE_LENGTH {
                        Err(format!("message length {length} over protocol maximum"))?;
                    }
                    stream.read_u32_le().await?; // checksum
                    let mut payload = vec![0u8; length as usize];
                    // read returns Ok on a short read, leaving a zero tail and misframing
                    // every later message. TCP segments a 25 KB addrv2 routinely.
                    stream.read_exact(&mut payload).await?;

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

    /// get_payload blocks until the peer sends a matching message or closes. Without a
    /// bound a silent peer hangs the crawl.
    async fn get_payload_within(
        &self,
        stream: &mut TcpStream,
        command: Option<[u8; 12]>,
        within: Duration,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        match tokio::time::timeout(within, self.get_payload(stream, command)).await {
            Ok(r) => r,
            Err(_) => Err("timed out waiting for peer".into()),
        }
    }

    pub async fn get_block_height(&self, payload: &[u8]) -> Result<u32, Box<dyn Error>> {
        let mut payload = Cursor::new(payload);
        payload.read_exact(&mut [0u8; 80]).await?;
        let user_agent_len = read_varint(&mut payload)?;
        // vec![0u8; n] panics rather than returning Err, and version is the first
        // message any peer sends, so unchecked this aborts the process.
        if user_agent_len > MAX_SUBVERSION_LENGTH {
            Err("user agent over MAX_SUBVERSION_LENGTH")?;
        }
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

            let addr_len = read_varint(&mut payload)?;
            if addr_len > MAX_ADDRV2_SIZE {
                Err("addrv2 entry over MAX_ADDRV2_SIZE")?;
            }
            let mut addr = vec![0u8; addr_len as usize];
            // read_exact, not read: Cursor::read short-reads on a truncated payload and
            // returns Ok, which leaves zero bytes in addr and desynchronises every
            // entry after it. A peer choosing the lengths controls where that lands.
            payload.read_exact(&mut addr).await?;
            payload.read_u16().await?; // port, big endian; the crawler dials the default

            // Only get nodes within TIME_CUTOFF, or we may get a bunch of garbage
            if i64::abs((time as i64) - (now as i64)) > TIME_CUTOFF {
                continue;
            }
            if let Some(ip) = decode_bip155_addr(network_id, &addr) {
                ips.entry(ip)
                    .and_modify(|i| *i = (*i).max(time))
                    .or_insert(time);
            }
        }

        Ok(())
    }

    /// Returns every address gossiped to us, and separately the subset that answered a
    /// block-hash query. The first is the census the tool exists to produce; folding the
    /// two together would silently drop every family this process cannot dial, which is
    /// the bug that made the crawler an IPv4-only counter in the first place.
    #[allow(clippy::type_complexity)]
    pub async fn get_peers(
        &self,
    ) -> Result<(HashMap<Ip, u32>, HashMap<Ip, (u32, Vec<BlockHash>)>), Box<dyn Error>> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.ip.as_ref(), network().port)).await?;
    
        self.send_version(&mut stream).await?;
        let version_payload = self.get_payload(&mut stream, Some(*b"version\0\0\0\0\0")).await?;
        let peer_height = self.get_block_height(&version_payload).await?;
        println!("Connected peer's block height: {}", peer_height);
    
        self.send_verack(&mut stream).await?;
        self.get_payload(&mut stream, Some(*b"verack\0\0\0\0\0\0")).await?;
    
        self.send_sendaddrv2(&mut stream).await?;
    
        let mut peers = HashMap::new();
    
        // Ask once. Core answers a repeated getaddr by clearing vAddrToSend and starting
        // over, so asking again mid-wait discards the reply being assembled. It splits
        // large replies across messages, so drain until the peer goes quiet.
        self.send_getaddr(&mut stream).await?;
        loop {
            match self
                .get_payload_within(&mut stream, Some(*b"addrv2\0\0\0\0\0\0"), ADDR_WAIT)
                .await
            {
                Ok(payload) => self.extract_ips(&payload, &mut peers).await?,
                Err(_) => break,
            }
        }
        if peers.is_empty() {
            println!("no addresses from {}", self.ip.as_ref());
        }
    
        // The census is complete here. Print it before anything that can fail or block,
        // or the tool's primary output sits behind an explorer request and one connect
        // timeout per peer.
        let mut by_family: HashMap<&str, usize> = HashMap::new();
        for ip in peers.keys() {
            *by_family.entry(ip.family()).or_default() += 1;
        }
        println!("found {} addresses, by family: {:?}", peers.len(), by_family);

        // Check blockbook for latest data
        let Ok(best_block_hash) = fetch_latest_block_hash_from_explorer().await else {
            // Fork detection needs a trusted tip; address counting does not. Losing the
            // explorer should not cost the census.
            println!("explorer unreachable, skipping fork detection");
            return Ok((peers, HashMap::new()));
        };
        // Map to store peer IPs with heights and recent hashes
        let mut peer_updates: HashMap<Ip, (u32, Vec<BlockHash>)> = HashMap::new();
        for peer_ip in peers.keys() {
            // Onion, I2P and CJDNS need a proxy this process does not have. Dialling one
            // buys a connect timeout and no data; it stays in the census regardless.
            if !peer_ip.is_directly_dialable() {
                continue;
            }
            // Connect once per peer
            let Ok(mut peer_stream) = TcpStream::connect(format!("{}:{}", peer_ip.as_ref(), network().port)).await else {
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
        Ok((peers, peer_updates))
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

    /// Returns addresses only. get_peers also collects block hashes, which needs a
    /// second round trip the caller does not always want.
    pub async fn get_basic_peers(&self) -> Result<Vec<Ip>, Box<dyn Error>> {
        let mut stream = TcpStream::connect(format!("{}:{}", self.ip.as_ref(), network().port)).await?;

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
#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 51472;

    fn now() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
    }

    /// One addrv2 entry: time LE, services CompactSize, network id, address CompactSize
    /// length, address, port BE. `declared_len` overrides the length field so a malformed
    /// entry can be built.
    fn entry(time: u32, network_id: u8, addr: &[u8], declared_len: Option<u8>) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&time.to_le_bytes());
        v.push(0x00);
        v.push(network_id);
        v.push(declared_len.unwrap_or(addr.len() as u8));
        v.extend_from_slice(addr);
        v.extend_from_slice(&PORT.to_be_bytes());
        v
    }

    fn addrv2(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![entries.len() as u8];
        for e in entries {
            v.extend_from_slice(e);
        }
        v
    }

    async fn parse(payload: &[u8]) -> Result<HashMap<Ip, u32>, Box<dyn Error>> {
        let node = Node {
            ip: Ip::Ip4("127.0.0.1".to_string()),
        };
        let mut ips = HashMap::new();
        node.extract_ips(payload, &mut ips).await?;
        Ok(ips)
    }

    fn base32_decode(s: &str) -> Vec<u8> {
        const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
        let (mut acc, mut bits, mut out) = (0u16, 0u8, Vec::new());
        for c in s.bytes() {
            let v = ALPHABET.iter().position(|&a| a == c).expect("base32 char") as u16;
            acc = (acc << 5) | v;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32_lower(b""), "");
        assert_eq!(base32_lower(b"f"), "my");
        assert_eq!(base32_lower(b"fo"), "mzxq");
        assert_eq!(base32_lower(b"foo"), "mzxw6");
        assert_eq!(base32_lower(b"foob"), "mzxw6yq");
        assert_eq!(base32_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
    }

    /// Published v3 onion addresses. A wrong checksum prefix or version byte would have
    /// to collide on 16 bits three times over to pass this.
    #[test]
    fn onion_v3_matches_published_addresses() {
        for addr in [
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
            "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
            "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion",
        ] {
            let raw = base32_decode(addr.strip_suffix(".onion").unwrap());
            assert_eq!(raw.len(), 35, "{addr}");
            let pubkey: [u8; 32] = raw[..32].try_into().unwrap();
            assert_eq!(onion_v3_address(&pubkey), addr);
        }
    }

    #[tokio::test]
    async fn records_every_reachable_family() {
        let t = now();
        let ips = parse(&addrv2(&[
            entry(t, BIP155_IPV4, &[51, 15, 45, 67], None),
            entry(t, BIP155_IPV6, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], None),
            entry(t, BIP155_TORV3, &[0xaa; 32], None),
            entry(t, BIP155_I2P, &[0xbb; 32], None),
            entry(t, BIP155_CJDNS, &[0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], None),
        ]))
        .await
        .unwrap();

        let mut families: Vec<&str> = ips.keys().map(|ip| ip.family()).collect();
        families.sort();
        assert_eq!(families, ["cjdns", "i2p", "ipv4", "ipv6", "onion"]);
        assert!(ips.contains_key(&Ip::Ip4("51.15.45.67".to_string())));
        assert!(ips.contains_key(&Ip::Ip6("2001:db8::1".to_string())));
        assert!(ips.contains_key(&Ip::Cjdns("fc00::1".to_string())));
        assert_eq!(
            ips.keys().find(|ip| ip.family() == "onion").unwrap().as_ref(),
            onion_v3_address(&[0xaa; 32])
        );
        assert!(ips
            .keys()
            .any(|ip| ip.family() == "i2p" && ip.as_ref().ends_with(".b32.i2p")));
    }

    /// Skipped entries must still advance the cursor, or every entry behind them decodes
    /// from the wrong offset. Each skipped kind is followed by a good IPv4 entry.
    #[tokio::test]
    async fn skipped_entries_do_not_desync_the_cursor() {
        let t = now();
        let good = entry(t, BIP155_IPV4, &[1, 2, 3, 4], None);
        for bad in [
            entry(t, BIP155_TORV2, &[0x11; 10], None),        // dead Tor v2
            entry(t, BIP155_IPV6, &[1, 2, 3, 4], None),       // id/length mismatch
            entry(t, BIP155_IPV4, &[0; 16], None),            // id/length mismatch
            entry(t, BIP155_TORV3, &[0xcc; 31], None),        // id/length mismatch
            entry(t, 0x07, &[0xdd; 8], None),                 // id not yet defined
            entry(t, 0x00, &[], None),                        // id 0 is not a network
        ] {
            let ips = parse(&addrv2(&[bad, good.clone()])).await.unwrap();
            assert_eq!(ips.len(), 1);
            assert!(ips.contains_key(&Ip::Ip4("1.2.3.4".to_string())));
        }
    }

    #[tokio::test]
    async fn rejects_hostile_lengths() {
        let t = now();
        // Declared length past MAX_ADDRV2_SIZE: must fail before allocating.
        let mut oversized = Vec::from([1u8]);
        oversized.extend_from_slice(&t.to_le_bytes());
        oversized.extend_from_slice(&[0x00, BIP155_IPV4, 0xfd, 0xff, 0xff]); // CompactSize 65535
        assert!(parse(&oversized).await.is_err());

        // Declared 16 bytes, 2 supplied. read_exact must error rather than zero-fill.
        let truncated = addrv2(&[entry(t, BIP155_IPV6, &[0xee, 0xee], Some(16))]);
        assert!(parse(&truncated).await.is_err());
    }

    #[tokio::test]
    async fn applies_time_cutoff_to_every_family() {
        let stale = now() - (TIME_CUTOFF as u32) - 60;
        let ips = parse(&addrv2(&[
            entry(stale, BIP155_IPV4, &[1, 2, 3, 4], None),
            entry(stale, BIP155_TORV3, &[0xaa; 32], None),
        ]))
        .await
        .unwrap();
        assert!(ips.is_empty());
    }

    #[tokio::test]
    async fn keeps_the_newest_timestamp_per_address() {
        let t = now();
        let ips = parse(&addrv2(&[
            entry(t - 100, BIP155_IPV4, &[1, 2, 3, 4], None),
            entry(t, BIP155_IPV4, &[1, 2, 3, 4], None),
            entry(t - 50, BIP155_IPV4, &[1, 2, 3, 4], None),
        ]))
        .await
        .unwrap();
        assert_eq!(ips[&Ip::Ip4("1.2.3.4".to_string())], t);
    }

    /// Crawls a real node and prints what it gossiped, by family. Ignored by default
    /// because it needs a reachable peer:
    ///   PIVX_CRAWLER_TEST_NODE=91.121.62.2 cargo test -- --ignored --nocapture
    /// Synthetic vectors cannot show whether real peers send these families.
    #[tokio::test]
    #[ignore]
    async fn crawls_a_live_node() {
        let node = Node {
            ip: Ip::Ip4(std::env::var("PIVX_CRAWLER_TEST_NODE").expect("PIVX_CRAWLER_TEST_NODE")),
        };
        let peers = node.get_basic_peers().await.expect("reachable peer");
        let mut by_family: HashMap<&str, usize> = HashMap::new();
        for ip in &peers {
            *by_family.entry(ip.family()).or_default() += 1;
        }
        println!("{} addresses, by family: {:?}", peers.len(), by_family);
        for ip in peers.iter().filter(|ip| !ip.is_directly_dialable()).take(5) {
            println!("  {}", ip.as_ref());
        }
        assert!(!peers.is_empty());
    }

    /// Onion, I2P and CJDNS have no legacy net_addr form; PIVX Core writes zeros.
    #[test]
    #[test]
    fn testnet_magic_is_testnet6() {
        // Shipped as testnet5's f5e6d5ca once. A wrong magic is dropped by peers, so it
        // reads as an empty network rather than an error.
        assert_eq!(crate::message::TESTNET.magic, 0xf6e7d6cb);
        assert_eq!(crate::message::TESTNET.port, 51474);
    }

    #[test]
    fn ipv4_mapped_under_ipv6_id_is_dropped() {
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..].copy_from_slice(&[51, 15, 45, 67]);
        assert_eq!(decode_bip155_addr(BIP155_IPV6, &mapped), None);

        // A real IPv6 address still decodes.
        let mut real = [0u8; 16];
        real[0] = 0x20;
        real[1] = 0x01;
        assert!(matches!(
            decode_bip155_addr(BIP155_IPV6, &real),
            Some(Ip::Ip6(_))
        ));
    }

    #[test]
    fn torv2_prefix_under_ipv6_id_is_dropped() {
        let mut v = [0u8; 16];
        v[..6].copy_from_slice(&TORV2_IN_IPV6_PREFIX);
        assert_eq!(decode_bip155_addr(BIP155_IPV6, &v), None);
    }

    #[tokio::test]
    async fn oversized_user_agent_errors_instead_of_panicking() {
        // 0xff + 8 bytes is a CompactSize of u64::MAX. vec![0u8; that] aborts the
        // process, which `?` cannot catch.
        let mut payload = vec![0u8; 80];
        payload.push(0xff);
        payload.extend_from_slice(&u64::MAX.to_le_bytes());
        let node = Node {
            ip: Ip::Ip4("127.0.0.1".to_string()),
        };
        assert!(node.get_block_height(&payload).await.is_err());
    }

    fn version_addr_bits_are_zero_for_proxied_networks() {
        assert_eq!(addr_bits(&Ip::Onion("x.onion".into())).unwrap(), 0);
        assert_eq!(addr_bits(&Ip::I2p("x.b32.i2p".into())).unwrap(), 0);
        assert_eq!(addr_bits(&Ip::Cjdns("fc00::1".into())).unwrap(), 0);
        assert_eq!(
            addr_bits(&Ip::Ip4("1.2.3.4".into())).unwrap(),
            Ipv6Addr::from_str("::ffff:1.2.3.4").unwrap().to_bits()
        );
        assert_eq!(
            addr_bits(&Ip::Ip6("2001:db8::1".into())).unwrap(),
            Ipv6Addr::from_str("2001:db8::1").unwrap().to_bits()
        );
    }
}
