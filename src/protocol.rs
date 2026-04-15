use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use crate::encryption::EncryptionService;
use crate::fragmentation;

use uuid::Uuid;

// --- Constants ---
pub const VERSION: &str = "v1.0.0";

pub const BITCHAT_SERVICE_UUID: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C);

pub const BITCHAT_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0xA1B2C3D4_E5F6_4A5B_8C9D_0E1F2A3B4C5D);

// Cover traffic prefix used by iOS for dummy messages
pub const COVER_TRAFFIC_PREFIX: &str = "☂DUMMY☂";

// Packet header flags
pub const FLAG_HAS_RECIPIENT: u8 = 0x01;
pub const FLAG_HAS_SIGNATURE: u8 = 0x02;
pub const FLAG_IS_COMPRESSED: u8 = 0x04;

pub const MSG_FLAG_IS_RELAY: u8 = 0x01;
pub const MSG_FLAG_IS_PRIVATE: u8 = 0x02;
pub const MSG_FLAG_HAS_ORIGINAL_SENDER: u8 = 0x04;
pub const MSG_FLAG_HAS_RECIPIENT_NICKNAME: u8 = 0x08;
pub const MSG_FLAG_HAS_SENDER_PEER_ID: u8 = 0x10;
pub const MSG_FLAG_HAS_MENTIONS: u8 = 0x20;
pub const MSG_FLAG_HAS_CHANNEL: u8 = 0x40;
pub const MSG_FLAG_IS_ENCRYPTED: u8 = 0x80;

#[allow(dead_code)]
pub const SIGNATURE_SIZE: usize = 64;  // Ed25519 signature size

// Swift's SpecialRecipients.broadcast = Data(repeating: 0xFF, count: 8)
pub const BROADCAST_RECIPIENT: [u8; 8] = [0xFF; 8];

// Debug levels
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DebugLevel {
    Clean = 0,    // Default - minimal output
    Basic = 1,    // Connection info, key exchanges
    Full = 2,     // All debug output
}

// Global debug level
pub static mut DEBUG_LEVEL: DebugLevel = DebugLevel::Clean;

// Debug macro for basic debug (level 1+)
#[macro_export]
macro_rules! debug_println {
    ($($arg:tt)*) => {
        unsafe {
            use $crate::protocol::DebugLevel;
            if $crate::protocol::DEBUG_LEVEL as u8 >= DebugLevel::Basic as u8 {
                println!($($arg)*);
            }
        }
    };
}

// Debug macro for full debug (level 2)
#[macro_export]
macro_rules! debug_full_println {
    ($($arg:tt)*) => {
        unsafe {
            use $crate::protocol::DebugLevel;
            if $crate::protocol::DEBUG_LEVEL as u8 >= DebugLevel::Full as u8 {
                println!($($arg)*);
            }
        }
    };
}

// --- Protocol Enums ---

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType { 
    Announce = 0x01, 
    KeyExchange = 0x02, 
    Leave = 0x03,
    Message = 0x04,
    FragmentStart = 0x05,
    FragmentContinue = 0x06,
    FragmentEnd = 0x07,
    ChannelAnnounce = 0x08,      // Channel status announcement (matches Swift v2 code)
    ChannelRetention = 0x09,     // Channel retention policy (matches Swift v2 code)
    DeliveryAck = 0x0A,          // Acknowledge message received
    DeliveryStatusRequest = 0x0B,  // Request delivery status
    ReadReceipt = 0x0C,          // Message has been read
}

// --- Protocol Structs ---

#[derive(Debug, Default, Clone)]
pub struct Peer { 
    pub nickname: Option<String> 
}

#[derive(Debug)]
pub struct BitchatPacket { 
    pub msg_type: MessageType, 
    pub _sender_id: Vec<u8>,  // Kept for protocol compatibility 
    pub sender_id_str: String,  // Add string version for easy comparison
    pub recipient_id: Option<Vec<u8>>,  // Add recipient ID
    pub recipient_id_str: Option<String>,  // Add string version of recipient
    pub payload: Vec<u8>,
    pub ttl: u8,  // Add TTL field
}

#[derive(Debug)]
pub struct BitchatMessage { 
    pub id: String, 
    pub content: String, 
    pub channel: Option<String>,
    pub is_encrypted: bool,
    pub encrypted_content: Option<Vec<u8>>,  // Store raw encrypted bytes
}

// Delivery confirmation structures matching iOS
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeliveryAck {
    #[serde(rename = "originalMessageID")]
    pub original_message_id: String,
    #[serde(rename = "ackID")]
    pub ack_id: String,
    #[serde(rename = "recipientID")]
    pub recipient_id: String,
    #[serde(rename = "recipientNickname")]
    pub recipient_nickname: String,
    pub timestamp: u64,
    #[serde(rename = "hopCount")]
    pub hop_count: u8,
}

// Track sent messages awaiting delivery confirmation
pub struct DeliveryTracker {
    pub pending_messages: HashMap<String, (String, SystemTime, bool)>, // message_id -> (content, sent_time, is_private)
    pub sent_acks: HashSet<String>, // Track ACK IDs we've already sent to prevent duplicates
}

impl DeliveryTracker {
    pub fn new() -> Self {
        Self {
            pending_messages: HashMap::new(),
            sent_acks: HashSet::new(),
        }
    }
    
    pub fn track_message(&mut self, message_id: String, content: String, is_private: bool) {
        self.pending_messages.insert(message_id, (content, SystemTime::now(), is_private));
    }
    
    pub fn mark_delivered(&mut self, message_id: &str) -> bool {
        self.pending_messages.remove(message_id).is_some()
    }
    
    pub fn should_send_ack(&mut self, ack_id: &str) -> bool {
        self.sent_acks.insert(ack_id.to_string())
    }
}

// Fragment reassembly tracking - using hex strings as keys (matching Swift)
pub struct FragmentCollector {
    pub fragments: HashMap<String, HashMap<u16, Vec<u8>>>,  // fragment_id_hex -> (index -> data)
    pub metadata: HashMap<String, (u16, u8, String)>,  // fragment_id_hex -> (total, original_type, sender_id)
}

impl FragmentCollector {
    pub fn new() -> Self {
        FragmentCollector {
            fragments: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
    
    pub fn add_fragment(&mut self, fragment_id: [u8; 8], index: u16, total: u16, original_type: u8, data: Vec<u8>, sender_id: String) -> Option<(Vec<u8>, String)> {
        // Convert fragment ID to hex string (matching Swift's hexEncodedString)
        let fragment_id_hex = fragment_id.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        
        debug_full_println!("[COLLECTOR] Adding fragment {} (index {}/{}) for ID {}", 
                index + 1, index + 1, total, &fragment_id_hex[..8]);
        
        // Initialize if first fragment
        if !self.fragments.contains_key(&fragment_id_hex) {
            debug_full_println!("[COLLECTOR] Creating new fragment collection for ID {}", &fragment_id_hex[..8]);
            self.fragments.insert(fragment_id_hex.clone(), HashMap::new());
            self.metadata.insert(fragment_id_hex.clone(), (total, original_type, sender_id.clone()));
        }
        
        // Add fragment data at index
        if let Some(fragment_map) = self.fragments.get_mut(&fragment_id_hex) {
            fragment_map.insert(index, data);
            debug_full_println!("[COLLECTOR] Fragment {} stored. Have {}/{} fragments", 
                    index + 1, fragment_map.len(), total);
            
            // Check if we have all fragments
            if fragment_map.len() == total as usize {
                debug_full_println!("[COLLECTOR] ✓ All fragments received! Reassembling...");
                
                // Reassemble in order
                let mut complete_data = Vec::new();
                for i in 0..total {
                    if let Some(fragment_data) = fragment_map.get(&i) {
                        debug_full_println!("[COLLECTOR] Appending fragment {} ({} bytes)", i + 1, fragment_data.len());
                        complete_data.extend_from_slice(fragment_data);
                    } else {
                        debug_full_println!("[COLLECTOR] ✗ Missing fragment {}", i + 1);
                        return None;
                    }
                }
                
                debug_full_println!("[COLLECTOR] ✓ Reassembly complete: {} bytes total", complete_data.len());
                
                // Get sender from metadata
                let sender = self.metadata.get(&fragment_id_hex)
                    .map(|(_, _, s)| s.clone())
                    .unwrap_or_else(|| "Unknown".to_string());
                
                // Clean up
                self.fragments.remove(&fragment_id_hex);
                self.metadata.remove(&fragment_id_hex);
                
                return Some((complete_data, sender));
            } else {
                debug_full_println!("[COLLECTOR] Waiting for more fragments ({}/{} received)", 
                        fragment_map.len(), total);
            }
        }
        
        None
    }
}

// --- Protocol Functions ---

pub fn unpad_message(data: &[u8]) -> Vec<u8> {
    if data.is_empty() { return Vec::new(); }
    let last_byte = data[data.len() - 1];
    if last_byte > 0 && last_byte as usize <= data.len() {
        let pad_len = last_byte as usize;
        let mut is_valid = true;
        for i in (data.len() - pad_len)..data.len() {
            if data[i] != last_byte {
                is_valid = false;
                break;
            }
        }
        if is_valid {
            return data[..data.len() - pad_len].to_vec();
        }
    }
    data.to_vec()
}

pub fn parse_bitchat_message_payload(data: &[u8]) -> Result<BitchatMessage, &'static str> {
    debug_full_println!("[PARSE] Parsing message payload, size: {} bytes", data.len());
    
    let mut offset = 0;

    if data.is_empty() { return Err("Payload too short for flags"); }

    let flags = data[offset];
    debug_full_println!("[PARSE] Flags: 0x{:02X}", flags);
    offset += 1;

    let mut message_id = String::new();
    if (flags & MSG_FLAG_HAS_ORIGINAL_SENDER) != 0 {
        if data.len() < offset + 16 { return Err("Payload too short for message ID"); }
        let id_bytes = &data[offset..offset+16];
        message_id = hex::encode(id_bytes);
        offset += 16;
    }

    let mut _sender_peer_id = String::new();
    if (flags & MSG_FLAG_HAS_SENDER_PEER_ID) != 0 {
        if data.len() < offset + 4 { return Err("Payload too short for sender peer ID"); }
        _sender_peer_id = hex::encode(&data[offset..offset+4]);
        offset += 4;
    }

    let mut channel = None;
    if (flags & MSG_FLAG_HAS_CHANNEL) != 0 {
        if data.len() < offset + 1 { return Err("Payload too short for channel len"); }
        let len = data[offset] as usize;
        offset += 1;
        if data.len() < offset + len { return Err("Payload too short for channel name"); }
        channel = Some(String::from_utf8_lossy(&data[offset..offset+len]).to_string());
        offset += len;
    }

    let mut _recipient_nick = None;
    if (flags & MSG_FLAG_HAS_RECIPIENT_NICKNAME) != 0 {
        if data.len() < offset + 1 { return Err("Payload too short for recipient len"); }
        let len = data[offset] as usize;
        offset += 1;
        if data.len() < offset + len { return Err("Payload too short for recipient nickname"); }
        _recipient_nick = Some(String::from_utf8_lossy(&data[offset..offset+len]).to_string());
        offset += len;
    }

    if (flags & MSG_FLAG_HAS_MENTIONS) != 0 {
        if data.len() < offset + 1 { return Err("Payload too short for mentions count"); }
        let count = data[offset] as usize;
        offset += 1;
        for _ in 0..count {
            if data.len() < offset + 1 { return Err("Payload too short for mention len"); }
            let len = data[offset] as usize;
            offset += 1;
            offset += len;
        }
    }

    let is_encrypted = (flags & MSG_FLAG_IS_ENCRYPTED) != 0;
    let mut encrypted_content = None;
    let mut content = String::new();

    if is_encrypted {
        encrypted_content = Some(data[offset..].to_vec());
        content = "[Encrypted message]".to_string();
    } else {
        content = String::from_utf8_lossy(&data[offset..]).to_string();
    }

    Ok(BitchatMessage {
        id: message_id,
        content,
        channel,
        is_encrypted,
        encrypted_content,
    })
}

pub fn create_bitchat_message_payload(sender: &str, content: &str, channel: Option<&str>) -> Vec<u8> {
    create_bitchat_message_payload_with_flags(sender, content, channel, false)
}

pub fn create_bitchat_message_payload_with_flags(sender: &str, content: &str, channel: Option<&str>, is_private: bool) -> Vec<u8> {
    let dummy_peer_id = "00000000"; // Should ideally pass real peer ID
    let (payload, _) = create_bitchat_message_payload_full(sender, content, channel, is_private, dummy_peer_id);
    payload
}

pub fn create_bitchat_message_payload_full(_sender: &str, content: &str, channel: Option<&str>, is_private: bool, sender_peer_id: &str) -> (Vec<u8>, String) {
    let mut data = Vec::new();
    
    let mut flags: u8 = MSG_FLAG_HAS_ORIGINAL_SENDER | MSG_FLAG_HAS_SENDER_PEER_ID;
    if is_private { flags |= MSG_FLAG_IS_PRIVATE; }
    if channel.is_some() { flags |= MSG_FLAG_HAS_CHANNEL; }
    
    data.push(flags);
    
    let message_id = Uuid::new_v4();
    data.extend_from_slice(message_id.as_bytes());
    
    let peer_id_bytes = hex::decode(sender_peer_id).unwrap_or_else(|_| vec![0; 4]);
    data.extend_from_slice(&peer_id_bytes[..4]);
    
    if let Some(ch) = channel {
        data.push(ch.len() as u8);
        data.extend_from_slice(ch.as_bytes());
    }
    
    data.extend_from_slice(content.as_bytes());
    
    (data, message_id.to_string())
}

pub fn parse_bitchat_packet(data: &[u8]) -> Result<BitchatPacket, &'static str> {
    if data.len() < 12 { return Err("Packet too short"); }
    
    let mut offset = 0;
    
    let _version = data[offset];
    offset += 1;
    
    let msg_type = match data[offset] {
        0x01 => MessageType::Announce,
        0x02 => MessageType::KeyExchange,
        0x03 => MessageType::Leave,
        0x04 => MessageType::Message,
        0x05 => MessageType::FragmentStart,
        0x06 => MessageType::FragmentContinue,
        0x07 => MessageType::FragmentEnd,
        0x08 => MessageType::ChannelAnnounce,
        0x09 => MessageType::ChannelRetention,
        0x0A => MessageType::DeliveryAck,
        0x0B => MessageType::DeliveryStatusRequest,
        0x0C => MessageType::ReadReceipt,
        _ => return Err("Unknown message type"),
    };
    offset += 1;
    
    let ttl = data[offset];
    offset += 1;
    
    let _timestamp = u64::from_be_bytes(data[offset..offset+8].try_into().unwrap());
    offset += 8;
    
    let flags = data[offset];
    offset += 1;
    
    let has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0;
    let has_signature = (flags & FLAG_HAS_SIGNATURE) != 0;
    let _is_compressed = (flags & FLAG_IS_COMPRESSED) != 0;

    if data.len() < offset + 4 { return Err("Packet too short for sender ID"); }
    let sender_id = data[offset..offset+4].to_vec();
    let sender_id_str = hex::encode(&sender_id);
    offset += 4;
    
    let mut recipient_id = None;
    let mut recipient_id_str = None;
    if has_recipient {
        if data.len() < offset + 8 { return Err("Packet too short for recipient ID"); }
        let rid = data[offset..offset+8].to_vec();
        recipient_id_str = Some(hex::encode(&rid));
        recipient_id = Some(rid);
        offset += 8;
    }
    
    if has_signature {
        if data.len() < offset + 64 { return Err("Packet too short for signature"); }
        offset += 64;
    }
    
    let payload = data[offset..].to_vec();
    
    Ok(BitchatPacket {
        msg_type,
        _sender_id: sender_id,
        sender_id_str,
        recipient_id,
        recipient_id_str,
        payload,
        ttl,
    })
}

pub fn create_bitchat_packet(sender_id_str: &str, msg_type: MessageType, payload: Vec<u8>) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, None, msg_type, payload, None)
}

pub fn create_bitchat_packet_with_signature(sender_id_str: &str, msg_type: MessageType, payload: Vec<u8>, signature: Option<Vec<u8>>) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, None, msg_type, payload, signature)
}

pub fn create_bitchat_packet_with_recipient_and_signature(sender_id_str: &str, recipient_id_str: &str, msg_type: MessageType, payload: Vec<u8>, signature: Option<Vec<u8>>) -> Vec<u8> {
    create_bitchat_packet_with_recipient(sender_id_str, Some(recipient_id_str), msg_type, payload, signature)
}

pub fn create_bitchat_packet_with_recipient(sender_id_str: &str, recipient_id_str: Option<&str>, msg_type: MessageType, payload: Vec<u8>, signature: Option<Vec<u8>>) -> Vec<u8> {
    let mut data = Vec::new();
    
    let version = 0x01;
    data.push(version);
    
    let msg_type_byte = msg_type as u8;
    data.push(msg_type_byte);
    
    let ttl = 7u8;
    data.push(ttl);
    
    let timestamp_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    data.extend_from_slice(&timestamp_ms.to_be_bytes());
    
    let mut flags: u8 = 0;
    let has_recipient = !matches!(msg_type, MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd);
    if has_recipient {
        flags |= FLAG_HAS_RECIPIENT;
    }
    if signature.is_some() {
        flags |= FLAG_HAS_SIGNATURE;
    }
    data.push(flags);
    
    let sender_id_bytes = hex::decode(sender_id_str).unwrap_or_else(|_| vec![0; 4]);
    data.extend_from_slice(&sender_id_bytes[..4]);
    
    if has_recipient {
        if let Some(recipient) = recipient_id_str {
            let recipient_bytes = hex::decode(recipient).unwrap_or_else(|_| BROADCAST_RECIPIENT.to_vec());
            data.extend_from_slice(&recipient_bytes);
            debug_full_println!("[PACKET] Recipient ID (private): {} -> {} bytes: {}", recipient, recipient_bytes.len(), hex::encode(&recipient_bytes));
        } else {
            data.extend_from_slice(&BROADCAST_RECIPIENT);
            debug_full_println!("[PACKET] Recipient ID (broadcast): {} bytes: {}", BROADCAST_RECIPIENT.len(), hex::encode(BROADCAST_RECIPIENT));
        }
    }
    
    if let Some(sig) = signature {
        data.extend_from_slice(&sig);
    }
    
    data.extend_from_slice(&payload);
    
    debug_full_println!("[PACKET] Packet created: type={:?}, size={}, recipient={}", 
                      msg_type, data.len(), hex::encode(BROADCAST_RECIPIENT));
                      
    data
}

pub fn create_delivery_ack(
    original_message_id: &str,
    recipient_id: &str,
    recipient_nickname: &str,
    hop_count: u8,
) -> Vec<u8> {
    let ack = DeliveryAck {
        original_message_id: original_message_id.to_string(),
        ack_id: Uuid::new_v4().to_string(),
        recipient_id: recipient_id.to_string(),
        recipient_nickname: recipient_nickname.to_string(),
        timestamp: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        hop_count,
    };
    
    serde_json::to_vec(&ack).unwrap_or_default()
}

pub fn create_encrypted_channel_message_payload(
    _sender: &str,
    content: &str,
    _channel: &str,
    channel_key: &[u8; 32],
    encryption_service: &EncryptionService,
    sender_peer_id: &str
) -> (Vec<u8>, String) {
    let mut data = Vec::new();
    
    let flags: u8 = MSG_FLAG_HAS_ORIGINAL_SENDER | MSG_FLAG_HAS_SENDER_PEER_ID | MSG_FLAG_HAS_CHANNEL | MSG_FLAG_IS_ENCRYPTED;
    data.push(flags);
    
    let message_id = Uuid::new_v4();
    data.extend_from_slice(message_id.as_bytes());
    
    let peer_id_bytes = hex::decode(sender_peer_id).unwrap_or_else(|_| vec![0; 4]);
    data.extend_from_slice(&peer_id_bytes[..4]);
    
    data.push(_channel.len() as u8);
    data.extend_from_slice(_channel.as_bytes());
    
    let encrypted = encryption_service.encrypt_with_key(content.as_bytes(), channel_key).unwrap_or_default();
    data.extend_from_slice(&encrypted);
    
    (data, message_id.to_string())
}

pub fn generate_keys_and_payload(encryption_service: &EncryptionService) -> (Vec<u8>, String) {
    let my_public_key = encryption_service.get_combined_public_key_data();
    let fingerprint = encryption_service.get_my_fingerprint();
    
    (my_public_key, fingerprint)
}

pub fn should_fragment(packet_data: &[u8]) -> bool {
    packet_data.len() > 180
}

pub fn create_fragment_packet(sender_id: &str, fragment: fragmentation::Fragment) -> Vec<u8> {
    let msg_type = match fragment.fragment_type {
        fragmentation::FragmentType::Start => MessageType::FragmentStart,
        fragmentation::FragmentType::Continue => MessageType::FragmentContinue,
        fragmentation::FragmentType::End => MessageType::FragmentEnd,
    };
    
    // Explicitly call serialize instead of to_bytes if to_bytes doesn't exist
    create_bitchat_packet(sender_id, msg_type, fragment.serialize())
}

pub fn should_send_ack(is_private: bool, channel: Option<&str>, mentions: Option<&Vec<String>>, _my_nickname: &str, active_peer_count: usize) -> bool {
    if is_private {
        // Always ACK private messages
        true
    } else if let Some(_) = channel {
        // For room messages, ACK if:
        // 1. Less than 10 active peers, OR
        // 2. We're mentioned
        if active_peer_count < 10 {
            return true;
        }
        
        if let Some(m) = mentions {
            if m.contains(&_my_nickname.to_string()) {
                return true;
            }
        }
        false
    } else {
        false
    }
}
