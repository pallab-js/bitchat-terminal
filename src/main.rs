use btleplug::api::{Central, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType};

use btleplug::platform::{Manager, Peripheral};

use tokio::io::{self, AsyncBufReadExt, BufReader};
use std::io::Write;

use tokio::sync::mpsc;

use tokio::time::{self, Duration};

use uuid::Uuid;

use futures::stream::StreamExt;

use std::collections::{HashMap, HashSet};

use std::convert::TryInto;

use std::sync::{Arc, Mutex};

use std::time::SystemTime;

use std::env;

use bloomfilter::Bloom;

// use ed25519_dalek::SigningKey; // Removed: unused

// use x25519_dalek::StaticSecret; // Removed: unused

// use rand::rngs::OsRng; // Removed: unused
use rand::Rng;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

mod compression;
mod fragmentation;
mod encryption;
mod terminal_ux;
mod persistence;
mod protocol;
mod ble;
mod commands;

use compression::decompress;
use fragmentation::{Fragment, FragmentType};
use encryption::EncryptionService;
use terminal_ux::{ChatContext, ChatMode, format_message_display, print_help, MessageDisplayConfig};
use persistence::{AppState, load_state, save_state, decrypt_password, create_app_state};
pub use protocol::{
    DebugLevel, DEBUG_LEVEL, MessageType, Peer, BitchatPacket, BitchatMessage, 
    DeliveryAck, DeliveryTracker, FragmentCollector, BROADCAST_RECIPIENT,
    MSG_FLAG_IS_RELAY, MSG_FLAG_IS_PRIVATE, MSG_FLAG_HAS_ORIGINAL_SENDER,
    MSG_FLAG_HAS_RECIPIENT_NICKNAME, MSG_FLAG_HAS_SENDER_PEER_ID,
    MSG_FLAG_HAS_MENTIONS, MSG_FLAG_HAS_CHANNEL, MSG_FLAG_IS_ENCRYPTED,
    VERSION, BITCHAT_SERVICE_UUID, BITCHAT_CHARACTERISTIC_UUID, COVER_TRAFFIC_PREFIX,
    FLAG_HAS_RECIPIENT, FLAG_HAS_SIGNATURE, FLAG_IS_COMPRESSED,
    unpad_message, parse_bitchat_message_payload, create_bitchat_message_payload,
    create_bitchat_message_payload_with_flags, create_bitchat_message_payload_full,
    create_encrypted_channel_message_payload, parse_bitchat_packet,
    generate_keys_and_payload, create_bitchat_packet, create_bitchat_packet_with_signature,
    create_bitchat_packet_with_recipient_and_signature, create_bitchat_packet_with_recipient,
    create_delivery_ack, should_send_ack, should_fragment, create_fragment_packet
};
pub use ble::{find_peripheral, send_packet_with_fragmentation, send_channel_announce};
use commands::CommandHandler;


#[tokio::main]

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    // Check for debug flags
    unsafe {
        if args.iter().any(|arg| arg == "-dd" || arg == "--debug-full") {
            DEBUG_LEVEL = DebugLevel::Full;
            println!("🐛 Debug mode: FULL (verbose output)");
        } else if args.iter().any(|arg| arg == "-d" || arg == "--debug") {
            DEBUG_LEVEL = DebugLevel::Basic;
            println!("🐛 Debug mode: BASIC (connection info)");
        }
        // Otherwise stays at Clean (default)
    }

    let (tx, mut rx) = mpsc::channel::<String>(10);

    tokio::spawn(async move {

        let mut stdin = BufReader::new(io::stdin()).lines();

        // Display ASCII art logo in Matrix green
        println!("\n\x1b[38;5;46m##\\       ##\\   ##\\               ##\\                  ##\\");
        println!("## |      \\__|  ## |              ## |                 ## |");
        println!("#######\\  ##\\ ######\\    #######\\ #######\\   ######\\ ######\\");
        println!("##  __##\\ ## |\\_##  _|  ##  _____|##  __##\\  \\____##\\\\_##  _|");
        println!("## |  ## |## |  ## |    ## /      ## |  ## | ####### | ## |");
        println!("## |  ## |## |  ## |##\\ ## |      ## |  ## |##  __## | ## |##\\");
        println!("#######  |## |  \\####  |\\#######\\ ## |  ## |\\####### | \\####  |");
        println!("\\_______/ \\__|   \\____/  \\_______|\\__|  \\__| \\_______|  \\____/\x1b[0m");
        println!("\n\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
        println!("\x1b[37mDecentralized • Encrypted • Peer-to-Peer • Open Source\x1b[0m");
        println!("\x1b[37m                bitch@ the terminal {}\x1b[0m", VERSION);
        println!("\x1b[38;5;40m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n");

        loop {
            // Note: We can't access chat_context here directly, but we'll improve this later
            print!("> ");
            use std::io::{self as stdio, Write};
            let _ = stdio::stdout().flush();

            if let Ok(Some(line)) = stdin.next_line().await {

                if tx.send(line).await.is_err() { break; }

            } else { break; }

        }

    });


    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    let adapter = match adapters.into_iter().next() {
        Some(adapter) => adapter,
        None => {
            println!("\n\x1b[91m❌ No Bluetooth adapter found\x1b[0m");
            println!("\x1b[90mPlease check:\x1b[0m");
            println!("\x1b[90m  • Your device has Bluetooth hardware\x1b[0m");
            println!("\x1b[90m  • Bluetooth is enabled in system settings\x1b[0m");
            println!("\x1b[90m  • You have permission to use Bluetooth\x1b[0m");
            return Ok(());
        }
    };

    adapter.start_scan(ScanFilter::default()).await?;

    println!("\x1b[90m» Scanning for bitchat service...\x1b[0m");
    debug_println!("[1] Scanning for bitchat service...");


    let peripheral = loop {

        if let Some(p) = find_peripheral(&adapter).await? {

            println!("\x1b[90m» Found bitchat service! Connecting...\x1b[0m");
            debug_println!("[1] Match Found! Connecting...");

            adapter.stop_scan().await?;

            break p;

        }

        time::sleep(Duration::from_secs(1)).await;

    };


    if let Err(e) = peripheral.connect().await {
        println!("\n\x1b[91m❌ Connection failed\x1b[0m");
        println!("\x1b[90mReason: {}\x1b[0m", e);
        println!("\x1b[90mPlease check:\x1b[0m");
        println!("\x1b[90m  • Bluetooth is enabled\x1b[0m");
        println!("\x1b[90m  • The other device is running BitChat\x1b[0m");
        println!("\x1b[90m  • You're within range\x1b[0m");
        println!("\n\x1b[90mTry running the command again.\x1b[0m");
        return Ok(());
    }


    peripheral.discover_services().await?;

    let characteristics = peripheral.characteristics();

    let cmd_char = characteristics.iter().find(|c| c.uuid == BITCHAT_CHARACTERISTIC_UUID).expect("Characteristic not found.");

    peripheral.subscribe(cmd_char).await?;

    let mut notification_stream = peripheral.notifications().await?;

    debug_println!("[2] Connection established.");
    
    // TODO: Implement MTU negotiation
    // Swift calls: peripheral.maximumWriteValueLength(for: .withoutResponse)
    // Default BLE MTU is 23 bytes (20 data), extended can be up to 512


    debug_println!("[3] Performing handshake...");

    // Generate peer ID like Swift does (4 random bytes as hex)
    let mut peer_id_bytes = [0u8; 4];
    rand::thread_rng().fill(&mut peer_id_bytes);
    let my_peer_id = hex::encode(peer_id_bytes);
    debug_full_println!("[DEBUG] My peer ID: {}", my_peer_id);
    
    // Load persisted state early to get saved nickname
    let mut app_state = load_state();
    let mut nickname = app_state.nickname.clone().unwrap_or_else(|| "my-rust-client".to_string());

    // Create encryption service
    let encryption_service = Arc::new(EncryptionService::new());
    let (key_exchange_payload, _) = generate_keys_and_payload(&encryption_service);

    let key_exchange_packet = create_bitchat_packet(&my_peer_id, MessageType::KeyExchange, key_exchange_payload);

    peripheral.write(cmd_char, &key_exchange_packet, WriteType::WithoutResponse).await?;

    // Add delay between key exchange and announce to ensure Android processes them properly
    time::sleep(Duration::from_millis(500)).await;

    let announce_packet = create_bitchat_packet(&my_peer_id, MessageType::Announce, nickname.as_bytes().to_vec());

    peripheral.write(cmd_char, &announce_packet, WriteType::WithoutResponse).await?;

    debug_println!("[3] Handshake sent. You can now chat.");
    if app_state.nickname.is_some() {
        println!("\x1b[90m» Using saved nickname: {}\x1b[0m", nickname);
    }
    println!("\x1b[90m» Type /status to see connection info\x1b[0m");


    let peers: Arc<Mutex<HashMap<String, Peer>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut bloom = Bloom::new_for_fp_rate(500, 0.01);

    let mut fragment_collector = FragmentCollector::new();
    let mut delivery_tracker = DeliveryTracker::new();

    let mut chat_context = ChatContext::new();
    let mut channel_keys: HashMap<String, [u8; 32]> = HashMap::new();
    let mut _chat_messages: HashMap<String, Vec<String>> = HashMap::new();  // for /clear command - stores messages by context
    
    // Already loaded app_state above for nickname
    let mut blocked_peers = app_state.blocked_peers.clone();
    let mut channel_creators = app_state.channel_creators.clone();
    let mut password_protected_channels = app_state.password_protected_channels.clone();
    let mut channel_key_commitments = app_state.channel_key_commitments.clone();
    let mut discovered_channels: HashSet<String> = HashSet::new();  // Track all discovered channels
    
    // Auto-restore channel keys from saved passwords (matching iOS behavior)
    if let Some(identity_key) = &app_state.identity_key {
        for (channel, encrypted_password) in &app_state.encrypted_channel_passwords {
            match decrypt_password(encrypted_password, identity_key) {
                Ok(password) => {
                    let key = EncryptionService::derive_channel_key(&password, channel);
                    channel_keys.insert(channel.clone(), key);
                    debug_println!("[CHANNEL] Restored key for password-protected channel: {}", channel);
                }
                Err(e) => {
                    debug_println!("[CHANNEL] Failed to restore key for {}: {}", channel, e);
                }
            }
        }
    }
    // Note: We don't restore joined_channels as they need to be re-joined via announce
    
    // Helper to create AppState for saving


    loop {
        tokio::select! {
            Some(line) = rx.recv() => {
                let mut handler = CommandHandler {
                    peripheral: &peripheral,
                    cmd_char: &cmd_char,
                    chat_context: &mut chat_context,
                    encryption_service: &encryption_service,
                    delivery_tracker: &mut delivery_tracker,
                    app_state: &mut app_state,
                    nickname: &mut nickname,
                    my_peer_id: &my_peer_id,
                    channel_keys: &mut channel_keys,
                    password_protected_channels: &mut password_protected_channels,
                    channel_creators: &mut channel_creators,
                    channel_key_commitments: &mut channel_key_commitments,
                    blocked_peers: &mut blocked_peers,
                    discovered_channels: &mut discovered_channels,
                    peers: &peers,
                };

                match handler.handle_command(&line).await {
                    Ok(true) => {},
                    Ok(false) => break,
                    Err(e) => eprintln!("Error handling command: {}", e),
                }
            },

            Some(notification) = notification_stream.next() => {
                // Simple packet logging
                if notification.value.len() >= 2 {
                    let msg_type = notification.value[1];
                    debug_full_println!("[PACKET] Received {} bytes, type: 0x{:02X}", notification.value.len(), msg_type);
                }
                
                match parse_bitchat_packet(&notification.value) {
                    Ok(packet) => {
                        // Ignore our own messages
                        if packet.sender_id_str == my_peer_id {
                            continue;
                        }

                     match packet.msg_type {

                         MessageType::Announce => {
                             let peer_nickname = String::from_utf8_lossy(&packet.payload).trim().to_string();

                             let mut peers_lock = peers.lock().unwrap();
                             let is_new_peer = !peers_lock.contains_key(&packet.sender_id_str);
                             let peer_entry = peers_lock.entry(packet.sender_id_str.clone()).or_default();

                             peer_entry.nickname = Some(peer_nickname.clone());
                             drop(peers_lock);

                             // Show connection notification in clean mode only for new peers
                             if is_new_peer {
                                 // Clear any existing prompt and show connection notification in yellow
                                 print!("\r\x1b[K\x1b[33m{} connected\x1b[0m\n> ", peer_nickname);
                                 std::io::stdout().flush().unwrap();
                             }
                             
                             debug_println!("[<-- RECV] Announce: Peer {} is now known as '{}'", packet.sender_id_str, peer_nickname);

                         },

                         MessageType::Message => {
                             debug_full_println!("[DEBUG] ==================== MESSAGE RECEIVED ====================");
                             debug_full_println!("[DEBUG] Sender: {}", packet.sender_id_str);
                             
                             // Check if sender is blocked
                             if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&packet.sender_id_str) {
                                 if blocked_peers.contains(&fingerprint) {
                                     debug_println!("[BLOCKED] Ignoring message from blocked peer: {}", packet.sender_id_str);
                                     continue; // Silent drop
                                 }
                             }
                             
                             // Check if this is a broadcast or targeted message
                             let is_broadcast = packet.recipient_id.as_ref()
                                 .map(|r| r == &BROADCAST_RECIPIENT)
                                 .unwrap_or(true);
                             
                             // Check if message is for us
                             let is_for_us = if is_broadcast {
                                 true
                             } else {
                                 packet.recipient_id_str.as_ref()
                                     .map(|r| {
                                         let matches = r == &my_peer_id;
                                         debug_full_println!("[DEBUG] Comparing recipient '{}' with my_peer_id '{}': {}", r, my_peer_id, matches);
                                         matches
                                     })
                                     .unwrap_or(false)
                             };
                             
                             if let Some(ref recipient) = packet.recipient_id_str {
                                 debug_full_println!("[DEBUG] Recipient: {} (broadcast: {})", recipient, is_broadcast);
                             } else {
                                 debug_full_println!("[DEBUG] Recipient: (none/broadcast)");
                             }
                             
                             debug_full_println!("[DEBUG] Payload size: {} bytes", packet.payload.len());
                             
                             // Handle messages not for us - relay them
                             if !is_for_us {
                                 debug_full_println!("[DEBUG] Message not for us, checking if we should relay (TTL={})", packet.ttl);
                                 
                                 // Relay if TTL > 1
                                 if packet.ttl > 1 {
                                     time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
                                     let mut relay_data = notification.value.clone();
                                     relay_data[2] = packet.ttl - 1;  // Decrement TTL
                                     
                                     if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
                                         println!("[!] Failed to relay message");
                                     } else {
                                         debug_full_println!("[DEBUG] Relayed message with TTL={}", packet.ttl - 1);
                                     }
                                 }
                                 continue;
                             }
                             
                             // iOS sends private messages with recipient ID set at packet level
                             let is_private_message = !is_broadcast && is_for_us;
                             let mut decrypted_payload = None;
                             
                             // If it's a private message for us, we need to decrypt it
                             if is_private_message {
                                 debug_println!("[PRIVATE] This is a private message for us from {}", packet.sender_id_str);
                                 debug_println!("[PRIVATE] Payload size: {} bytes", packet.payload.len());
                                 debug_println!("[PRIVATE] First 32 bytes of encrypted payload: {}", hex::encode(&packet.payload[..std::cmp::min(32, packet.payload.len())]));
                                 
                                 match encryption_service.decrypt(&packet.payload, &packet.sender_id_str) {
                                     Ok(decrypted) => {
                                         debug_println!("[PRIVATE] Successfully decrypted private message!");
                                         debug_println!("[PRIVATE] Decrypted size: {} bytes", decrypted.len());
                                         decrypted_payload = Some(decrypted);
                                     }
                                     Err(e) => {
                                         debug_println!("[PRIVATE] Failed to decrypt private message: {:?}", e);
                                         debug_println!("[PRIVATE] Checking if we have shared secret with {}", packet.sender_id_str);
                                         // Private messages MUST be encrypted, skip if decryption fails
                                         continue;
                                     }
                                 }
                             }
                             
                             
                             // Parse the message payload
                             let parse_result = if is_private_message {
                                 // For private messages, parse the decrypted and unpadded payload
                                 if let Some(ref decrypted) = decrypted_payload {
                                     debug_full_println!("[DEBUG] Parsing decrypted private message payload");
                                     let unpadded = unpad_message(decrypted);
                                     debug_full_println!("[DEBUG] After unpadding: {} bytes", unpadded.len());
                                     parse_bitchat_message_payload(&unpadded)
                                 } else {
                                     // If decryption failed but it's a private message, skip it
                                     debug_full_println!("[DEBUG] Cannot parse private message without decryption");
                                     continue;
                                 }
                             } else {
                                 // For broadcast messages, parse the payload directly
                                 debug_full_println!("[DEBUG] Parsing regular message payload");
                                 parse_bitchat_message_payload(&packet.payload)
                             };

                             if let Ok(message) = parse_result {
                                 debug_full_println!("[DEBUG] Message parsed successfully!");
                                 debug_full_println!("[DEBUG] Message ID: {}", message.id);
                                 debug_full_println!("[DEBUG] Is encrypted channel: {}", message.is_encrypted);
                                 debug_full_println!("[DEBUG] Channel: {:?}", message.channel);
                                 debug_full_println!("[DEBUG] Content length: {} bytes", message.content.len());

                                 if !bloom.check(&message.id) {
                                     // Add to bloom filter immediately to prevent duplicate processing
                                     bloom.set(&message.id);

                                     let sender_nick = {
                                         let peers_lock = peers.lock().unwrap();
                                         peers_lock.get(&packet.sender_id_str)
                                             .and_then(|p| p.nickname.as_ref())
                                             .cloned()
                                             .unwrap_or_else(|| packet.sender_id_str.clone())
                                     };

                                        // Track discovered channels
                                        if let Some(channel) = &message.channel {
                                            discovered_channels.insert(channel.clone());
                                            debug_println!("[DISCOVERY] Found channel: {}", channel);
                                            
                                            // Mark channel as password-protected if we see an encrypted message
                                            if message.is_encrypted {
                                                password_protected_channels.insert(channel.clone());
                                                debug_println!("[SECURITY] Marked {} as password-protected", channel);
                                            }
                                        }

                                        {
                                            // Normal message display with decryption support
                                            let display_content = if message.is_encrypted {
                                                if let Some(channel) = &message.channel {
                                                    if let Some(channel_key) = channel_keys.get(channel) {
                                                        // Decrypt the encrypted content
                                                        if let Some(encrypted_bytes) = &message.encrypted_content {
                                                            match encryption_service.decrypt_with_key(encrypted_bytes, channel_key) {
                                                            Ok(decrypted) => String::from_utf8_lossy(&decrypted).to_string(),
                                                                Err(_) => "[Encrypted message - decryption failed]".to_string()
                                                            }
                                                        } else {
                                                            "[Encrypted message - no encrypted data]".to_string()
                                                        }
                                                    } else {
                                                        "[Encrypted message - join channel with password]".to_string()
                                                    }
                                                } else {
                                                    message.content.clone()
                                                }
                                            } else {
                                                message.content.clone()
                                            };

                                            // Display the message with proper formatting
                                            let timestamp = chrono::Local::now();
                                            
                                            if is_private_message {
                                                // Check for iOS cover traffic (dummy messages)
                                                if display_content.starts_with(COVER_TRAFFIC_PREFIX) {
                                                    debug_println!("[COVER] Discarding dummy message from {}", sender_nick);
                                                    continue; // Silently discard cover traffic
                                                }
                                                
                                                // Save the last private sender for replies
                                                chat_context.last_private_sender = Some((packet.sender_id_str.clone(), sender_nick.to_string()));
                                                chat_context.add_dm(&sender_nick, &packet.sender_id_str);
                                                
                                use terminal_ux::MessageDisplayConfig;
                                let display = format_message_display(MessageDisplayConfig {
                                    timestamp,
                                    sender: &sender_nick,
                                    content: &display_content,
                                    is_private: true,
                                    is_channel: false,
                                    channel_name: None,
                                    recipient: Some(&nickname),
                                    my_nickname: &nickname,
                                });
                                                // Clear any existing prompt and print the message
                                                print!("\r\x1b[K{}\n", display);
                                                
                                                // Show minimal reply hint
                                                if !matches!(&chat_context.current_mode, ChatMode::PrivateDM { .. }) {
                                                    println!("\x1b[90m» /reply to respond\x1b[0m");
                                                }
                                                print!("> ");
                                                std::io::stdout().flush().unwrap();
                                                
                                                // Update last sender for /reply command
                                            } else if let Some(channel_name) = &message.channel {
                                                // Track this channel
                                                chat_context.add_channel(channel_name);
                                                
                                                let display = format_message_display(MessageDisplayConfig {
                                                    timestamp,
                                                    sender: &sender_nick,
                                                    content: &display_content,
                                                    is_private: false,
                                                    is_channel: true,
                                                    channel_name: Some(channel_name),
                                                    recipient: None,
                                                    my_nickname: &nickname,
                                                });
                                                // Clear any existing prompt and print the message
                                                print!("\r\x1b[K{}\n", display);
                                                std::io::stdout().flush().unwrap();
                                            } else {
                                                // Public message
                                                let display = format_message_display(MessageDisplayConfig {
                                                    timestamp,
                                                    sender: &sender_nick,
                                                    content: &display_content,
                                                    is_private: false,
                                                    is_channel: false,
                                                    channel_name: None,
                                                    recipient: None,
                                                    my_nickname: &nickname,
                                                });
                                                // Clear any existing prompt and print the message
                                                print!("\r\x1b[K{}\n> ", display);
                                                std::io::stdout().flush().unwrap();
                                            }
                                        }
                                     
                                     // Send delivery ACK if needed (matching iOS behavior)
                                     let active_peer_count = {
                                         let peers_lock = peers.lock().unwrap();
                                         peers_lock.len()
                                     };
                                     if should_send_ack(is_private_message, message.channel.as_deref(), None, &nickname, active_peer_count) {
                                         // Check if we've already sent an ACK for this message
                                         let ack_id = format!("{}-{}", message.id, my_peer_id);
                                         if delivery_tracker.should_send_ack(&ack_id) {
                                             debug_println!("[ACK] Sending delivery ACK for message {}", message.id);
                                             
                                             // Create ACK payload
                                             let ack_payload = create_delivery_ack(
                                                 &message.id,
                                                 &my_peer_id,
                                                 &nickname,
                                                 1 // hop count
                                             );
                                             
                                             // Encrypt ACK if it's a private message
                                             let final_ack_payload = if is_private_message {
                                                 // Encrypt the ACK for the sender
                                                 match encryption_service.encrypt_for_peer(&packet.sender_id_str, &ack_payload) {
                                                     Ok(encrypted) => encrypted,
                                                     Err(e) => {
                                                         debug_println!("[ACK] Failed to encrypt ACK: {:?}", e);
                                                         ack_payload
                                                     }
                                                 }
                                             } else {
                                                 ack_payload
                                             };
                                             
                                             // Create and send ACK packet with TTL=3 (limited propagation)
                                             let mut ack_packet = create_bitchat_packet_with_recipient(
                                                 &my_peer_id, 
                                                 Some(&packet.sender_id_str),
                                                 MessageType::DeliveryAck, 
                                                 final_ack_payload,
                                                 None // No signature for ACKs
                                             );
                                             
                                             // Override TTL to 3 for ACKs
                                             if ack_packet.len() > 2 {
                                                 ack_packet[2] = 3; // TTL position
                                             }
                                             
                                             if let Err(e) = peripheral.write(cmd_char, &ack_packet, WriteType::WithoutResponse).await {
                                                 debug_println!("[ACK] Failed to send delivery ACK: {}", e);
                                             }
                                         }
                                     }

                                     // Relay message if TTL > 1 (matching Swift behavior)
                                     if packet.ttl > 1 {
                                         // Don't relay immediately - add small random delay
                                         time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
                                         
                                         // Create relay packet with decremented TTL
                                         let mut relay_data = notification.value.clone();
                                         relay_data[2] = packet.ttl - 1;  // Decrement TTL at position 2
                                         
                                         if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
                                             println!("[!] Failed to relay message");
                                         }
                                     }

                                 }

                             } else {
                                 println!("[!] Failed to parse message payload");
                                 debug_full_println!("[DEBUG] Parse error details:");
                                 debug_full_println!("[DEBUG] Raw payload hex: {}", hex::encode(&packet.payload));
                                 if let Some(decrypted) = decrypted_payload {
                                     debug_full_println!("[DEBUG] Decrypted payload hex: {}", hex::encode(&decrypted));
                                 }
                             }

                         },
                         MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => {
                             // Handle fragment (simplified, following working example)
                             if packet.payload.len() >= 13 {
                                 let mut fragment_id = [0u8; 8];
                                 fragment_id.copy_from_slice(&packet.payload[0..8]);
                                 
                                 let index = ((packet.payload[8] as u16) << 8) | (packet.payload[9] as u16);
                                 let total = ((packet.payload[10] as u16) << 8) | (packet.payload[11] as u16);
                                 let original_type = packet.payload[12];
                                 let fragment_data = packet.payload[13..].to_vec();
                                 
                                 // Try to reassemble
                                 if let Some((complete_data, _sender)) = fragment_collector.add_fragment(
                                     fragment_id, index, total, original_type, fragment_data, packet.sender_id_str.clone()
                                 ) {
                                     // Parse and handle the reassembled packet
                                     if let Ok(reassembled_packet) = parse_bitchat_packet(&complete_data) {
                                         if reassembled_packet.msg_type == MessageType::Message {
                                             // Check if sender is blocked
                                             if let Some(fingerprint) = encryption_service.get_peer_fingerprint(&reassembled_packet.sender_id_str) {
                                                 if blocked_peers.contains(&fingerprint) {
                                                     debug_println!("[BLOCKED] Ignoring fragmented message from blocked peer: {}", reassembled_packet.sender_id_str);
                                                     continue; // Silent drop
                                                 }
                                             }
                                             
                                             // Check if this is a private message that needs decryption
                                             let is_broadcast = reassembled_packet.recipient_id.as_ref()
                                                 .map(|r| r == &BROADCAST_RECIPIENT)
                                                 .unwrap_or(true);
                                             
                                             let is_for_us = if is_broadcast {
                                                 true
                                             } else {
                                                 reassembled_packet.recipient_id_str.as_ref()
                                                     .map(|r| r == &my_peer_id)
                                                     .unwrap_or(false)
                                             };
                                             
                                             let is_private_message = !is_broadcast && is_for_us;
                                             
                                             // Handle private messages by decrypting first
                                             let message_result = if is_private_message {
                                                 match encryption_service.decrypt(&reassembled_packet.payload, &reassembled_packet.sender_id_str) {
                                                     Ok(decrypted) => {
                                                         debug_println!("[PRIVATE] Successfully decrypted fragmented private message!");
                                                         debug_println!("[PRIVATE] Decrypted size: {} bytes", decrypted.len());
                                                         let unpadded = unpad_message(&decrypted);
                                                         debug_full_println!("[DEBUG] After unpadding: {} bytes", unpadded.len());
                                                         parse_bitchat_message_payload(&unpadded)
                                                     },
                                                     Err(e) => {
                                                         debug_println!("[PRIVATE] Failed to decrypt fragmented private message: {:?}", e);
                                                         continue;
                                                     }
                                                 }
                                             } else {
                                                 // Regular broadcast message
                                                 parse_bitchat_message_payload(&reassembled_packet.payload)
                                             };
                                             
                                             if let Ok(message) = message_result {
                                                 if !bloom.check(&message.id) {
                                                     let sender_nick = {
                                                         let peers_lock = peers.lock().unwrap();
                                                         peers_lock.get(&reassembled_packet.sender_id_str)
                                                             .and_then(|p| p.nickname.as_ref())
                                                             .cloned()
                                                             .unwrap_or_else(|| reassembled_packet.sender_id_str.clone())
                                                     };
                                                     
                                                     {
                                                         // Track discovered channels from fragmented messages
                                                         if let Some(channel) = &message.channel {
                                                             discovered_channels.insert(channel.clone());
                                                             if message.is_encrypted {
                                                                 password_protected_channels.insert(channel.clone());
                                                             }
                                                         }
                                                         
                                                         // Check for iOS cover traffic in private messages
                                                         if is_private_message && message.content.starts_with(COVER_TRAFFIC_PREFIX) {
                                                             debug_println!("[COVER] Discarding fragmented dummy message from {}", sender_nick);
                                                             bloom.set(&message.id); // Mark as seen before continuing
                                                             continue; // Silently discard
                                                         }
                                                         
                                                         // Regular message - display it
                                                         let timestamp = chrono::Local::now();
                                                         let display = format_message_display(MessageDisplayConfig {
                                                             timestamp,
                                                             sender: &sender_nick,
                                                             content: &message.content,
                                                             is_private: is_private_message,
                                                             is_channel: message.channel.is_some(),
                                                             channel_name: message.channel.as_deref(),
                                                             recipient: if is_private_message { Some(&nickname) } else { None },
                                                             my_nickname: &nickname,
                                                         });
                                                         // Clear any existing prompt and print the message
                                                print!("\r\x1b[K{}\n> ", display);
                                                std::io::stdout().flush().unwrap();
                                                         
                                                         // If it's a private message, update chat context
                                                         if is_private_message {
                                                             chat_context.last_private_sender = Some((reassembled_packet.sender_id_str.clone(), sender_nick.to_string()));
                                                         }
                                                     }
                                                     
                                                     bloom.set(&message.id);
                                                 }
                                             }
                                         }
                                     }
                                 }
                             }
                             
                             // Relay fragments if TTL > 1
                             if packet.ttl > 1 {
                                 time::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..50))).await;
                                 let mut relay_data = notification.value.clone();
                                 relay_data[2] = packet.ttl - 1;
                                 
                                 if peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await.is_err() {
                                     println!("[!] Failed to relay fragment");
                                 }
                             }
                         },
                         MessageType::KeyExchange => {
                             // Extract public key
                             let public_key = packet.payload.clone();
                             debug_println!("[<-- RECV] Key exchange from {} (key: {} bytes)", packet.sender_id_str, public_key.len());
                             debug_full_println!("[CRYPTO] Key exchange payload first 32 bytes: {}", hex::encode(&public_key[..std::cmp::min(32, public_key.len())]));
                             
                             // Add peer's public key to encryption service
                             if let Err(e) = encryption_service.add_peer_public_key(&packet.sender_id_str, &public_key) {
                                 println!("[!] Failed to add peer public key: {:?}", e);
                             } else {
                                 debug_println!("[+] Successfully added encryption keys for peer {}", packet.sender_id_str);
                                 
                                 // Send our key exchange back if we haven't already
                                 let should_send_response = {
                                     let peers_lock = peers.lock().unwrap();
                                     !peers_lock.contains_key(&packet.sender_id_str)
                                 };

                                 if should_send_response {
                                     debug_full_println!("[CRYPTO] Sending key exchange response to {}", packet.sender_id_str);
                                     let (key_exchange_payload, _) = generate_keys_and_payload(&encryption_service);
                                     let key_exchange_packet = create_bitchat_packet(&my_peer_id, MessageType::KeyExchange, key_exchange_payload);
                                     if let Err(e) = peripheral.write(cmd_char, &key_exchange_packet, WriteType::WithoutResponse).await {
                                         println!("[!] Failed to send key exchange response: {}", e);
                                     }
                                 }
                             }
                         },
                         MessageType::Leave => {
                             // Handle leave notification
                             let payload_str = String::from_utf8_lossy(&packet.payload).trim().to_string();
                             
                             if payload_str.starts_with('#') {
                                 // Channel leave notification
                                 let channel = payload_str;
                                 let sender_nick = {
                                     let peers_lock = peers.lock().unwrap();
                                     peers_lock.get(&packet.sender_id_str)
                                         .and_then(|p| p.nickname.as_ref())
                                         .cloned()
                                         .unwrap_or_else(|| packet.sender_id_str.clone())
                                 };
                                 
                                 // Show leave message only if we're in that channel
                                 if let ChatMode::Channel(current_channel) = &chat_context.current_mode {
                                     if current_channel == &channel {
                                         print!("\r\x1b[K\x1b[90m« {} left {}\x1b[0m\n> ", sender_nick, channel);
                                         std::io::stdout().flush().unwrap();
                                     }
                                 }
                                 
                                 debug_println!("[<-- RECV] {} left channel {}", sender_nick, channel);
                             } else {
                                 // Legacy peer disconnect
                                 {
                                     let mut peers_lock = peers.lock().unwrap();
                                     peers_lock.remove(&packet.sender_id_str);
                                 }
                                 debug_println!("[<-- RECV] Peer {} ({}) has left", packet.sender_id_str, payload_str);
                             }
                         },
                         
                         MessageType::ChannelAnnounce => {
                             // Parse channel announce: "channel|isProtected|creatorID|keyCommitment"
                             let payload_str = String::from_utf8_lossy(&packet.payload);
                             let parts: Vec<&str> = payload_str.split('|').collect();
                             
                             if parts.len() >= 3 {
                                 let channel = parts[0];
                                 let is_protected = parts[1] == "1";
                                 let creator_id = parts[2];
                                 let _key_commitment = parts.get(3).unwrap_or(&"");
                                 
                                 debug_println!("[<-- RECV] Channel announce: {} (protected: {}, owner: {})", 
                                              channel, is_protected, creator_id);
                                
                                // Always update channel creator for any channel announce
                                if !creator_id.is_empty() {
                                    channel_creators.insert(channel.to_string(), creator_id.to_string());
                                }
                                 
                                 if is_protected {
                                     password_protected_channels.insert(channel.to_string());
                                     
                                     // Store key commitment for verification (matching iOS behavior)
                                     if !_key_commitment.is_empty() {
                                         channel_key_commitments.insert(channel.to_string(), _key_commitment.to_string());
                                         debug_println!("[CHANNEL] Stored key commitment for {}: {}", channel, _key_commitment);
                                     }
                                 } else {
                                     password_protected_channels.remove(channel);
                                     // If channel is no longer protected, clear keys and commitments
                                     channel_keys.remove(channel);
                                     channel_key_commitments.remove(channel);
                                 }
                                 
                                 // Track this channel
                                 chat_context.add_channel(channel);
                                 
                                 // Save state
                                 let state_to_save = create_app_state(
                                     &blocked_peers,
                                     &channel_creators,
                                     &chat_context.active_channels,
                                     &password_protected_channels,
                                     &channel_key_commitments,
                                     &app_state.encrypted_channel_passwords,
                                     &nickname,
                                     app_state.identity_key.clone(),
                                     &app_state.favorites
                                 );
                                 if let Err(e) = save_state(&state_to_save) {
                                     eprintln!("Warning: Could not save state: {}", e);
                                 }
                             }
                         },

                         MessageType::DeliveryAck => {
                            debug_println!("[<-- RECV] Delivery ACK from {}", packet.sender_id_str);
                            
                            // Check if this ACK is for us
                            let is_for_us = packet.recipient_id_str.as_ref()
                                .map(|r| r == &my_peer_id)
                                .unwrap_or(false);
                            
                            if is_for_us {
                                // Decrypt the ACK payload if it's encrypted
                                let ack_payload = if packet.ttl == 3 && encryption_service.has_peer_key(&packet.sender_id_str) {
                                    // ACKs might be encrypted for private messages
                                    match encryption_service.decrypt(&packet.payload, &packet.sender_id_str) {
                                        Ok(decrypted) => decrypted,
                                        Err(_) => packet.payload.clone() // Fall back to unencrypted
                                    }
                                } else {
                                    packet.payload.clone()
                                };
                                
                                // Parse the ACK JSON
                                if let Ok(ack) = serde_json::from_slice::<DeliveryAck>(&ack_payload) {
                                    debug_println!("[ACK] Received ACK for message: {}", ack.original_message_id);
                                    debug_println!("[ACK] From: {} ({})", ack.recipient_nickname, ack.recipient_id);
                                    
                                    // Mark message as delivered
                                    if delivery_tracker.mark_delivered(&ack.original_message_id) {
                                        // Show delivery confirmation
                                        print!("\r\x1b[K\x1b[90m✓ Delivered to {}\x1b[0m\n> ", ack.recipient_nickname);
                                        std::io::stdout().flush().unwrap();
                                    }
                                } else {
                                    debug_println!("[ACK] Failed to parse delivery ACK");
                                }
                            } else if packet.ttl > 1 {
                                // Relay ACK if not for us
                                let mut relay_data = notification.value.clone();
                                relay_data[2] = packet.ttl - 1;
                                let _ = peripheral.write(cmd_char, &relay_data, WriteType::WithoutResponse).await;
                            }
                        },
                        
                        MessageType::DeliveryStatusRequest => {
                            // iOS defines this but doesn't implement it yet
                            debug_println!("[<-- RECV] Delivery status request (not implemented)");
                        },
                        
                        MessageType::ReadReceipt => {
                            // iOS defines this but doesn't implement it yet
                            debug_println!("[<-- RECV] Read receipt (not implemented)");
                        },
                        
                        _ => {}

                     }
                    },
                    Err(_e) => {
                        // Silently ignore unparseable packets (following working example)
                    }
                }
            },

             _ = tokio::signal::ctrl_c() => { break; }

        }

    }


    debug_println!("\n[+] Disconnecting...");

    Ok(())

}
