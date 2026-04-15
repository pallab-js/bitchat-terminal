use btleplug::api::{Characteristic, WriteType, Peripheral as _};
use btleplug::platform::Peripheral;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use crate::{debug_println, protocol::{
    MessageType, create_bitchat_packet, create_bitchat_packet_with_recipient_and_signature,
    create_bitchat_packet_with_signature, create_bitchat_message_payload,
    create_bitchat_message_payload_full, create_encrypted_channel_message_payload,
    should_fragment, DeliveryTracker, VERSION, BROADCAST_RECIPIENT,
    COVER_TRAFFIC_PREFIX, Peer
}};
use crate::terminal_ux::{ChatContext, ChatMode, MessageDisplayConfig, format_message_display};
use crate::encryption::EncryptionService;
use crate::persistence::{AppState, save_state, encrypt_password, create_app_state};
use crate::ble::send_packet_with_fragmentation;
use uuid::Uuid;
use std::sync::{Arc, Mutex};

pub struct CommandHandler<'a> {
    pub peripheral: &'a Peripheral,
    pub cmd_char: &'a Characteristic,
    pub chat_context: &'a mut ChatContext,
    pub encryption_service: &'a EncryptionService,
    pub delivery_tracker: &'a mut DeliveryTracker,
    pub app_state: &'a mut AppState,
    pub nickname: &'a mut String,
    pub my_peer_id: &'a str,
    pub channel_keys: &'a mut HashMap<String, [u8; 32]>,
    pub password_protected_channels: &'a mut HashSet<String>,
    pub channel_creators: &'a mut HashMap<String, String>,
    pub channel_key_commitments: &'a mut HashMap<String, String>,
    pub blocked_peers: &'a mut HashSet<String>,
    pub discovered_channels: &'a mut HashSet<String>,
    pub peers: &'a Arc<Mutex<HashMap<String, Peer>>>,
}

impl<'a> CommandHandler<'a> {
    pub async fn handle_command(&mut self, line: &str) -> Result<bool, Box<dyn std::error::Error>> {
        if line.is_empty() { return Ok(true); }

        // Handle number switching first
        if line.len() == 1 {
            if let Ok(num) = line.parse::<usize>() {
                if self.chat_context.switch_to_number(num) {
                    debug_println!("{}", self.chat_context.get_status_line());
                } else {
                    println!("» Invalid conversation number");
                }
                return Ok(true);
            }
        }

        if line == "/help" {
            crate::terminal_ux::print_help();
            return Ok(true);
        }

        // Handle /name command
        if let Some(stripped) = line.strip_prefix("/name ") {
            let new_name = stripped.trim();
            if new_name.is_empty() {
                println!("\x1b[93m⚠ Usage: /name <new_nickname>\x1b[0m");
            } else if new_name.len() > 20 {
                println!("\x1b[93m⚠ Nickname too long\x1b[0m");
            } else {
                *self.nickname = new_name.to_string();
                self.app_state.nickname = Some(self.nickname.clone());
                
                let state_to_save = self.create_current_app_state();
                let _ = save_state(&state_to_save);

                let announce_packet = create_bitchat_packet(self.my_peer_id, MessageType::Announce, self.nickname.as_bytes().to_vec());
                let _ = self.peripheral.write(self.cmd_char, &announce_packet, WriteType::WithoutResponse).await;
                println!("\x1b[92m✓ Nickname changed to {}\x1b[0m", self.nickname);
            }
            return Ok(true);
        }

        if line == "/list" {
            self.chat_context.show_conversation_list();
            return Ok(true);
        }

        if line == "/public" {
            self.chat_context.switch_to_public();
            debug_println!("{}", self.chat_context.get_status_line());
            return Ok(true);
        }

        if line == "/reply" {
            if let Some((peer_id, nickname)) = self.chat_context.last_private_sender.clone() {
                self.chat_context.enter_dm_mode(&nickname, &peer_id);
                debug_println!("{}", self.chat_context.get_status_line());
            } else {
                println!("» No private messages received yet.");
            }
            return Ok(true);
        }

        if line == "/online" || line == "/w" {
            let peers_lock = self.peers.lock().unwrap();
            if peers_lock.is_empty() {
                println!("» No one else is online right now.");
            } else {
                let mut online_list: Vec<String> = peers_lock.iter()
                    .filter_map(|(_, peer)| peer.nickname.clone())
                    .collect();
                online_list.sort();
                println!("» Online users: {}", online_list.join(", "));
            }
            print!("> ");
            std::io::stdout().flush().unwrap();
            return Ok(true);
        }

        if line == "/status" {
            let peer_count = self.peers.lock().unwrap().len();
            let channel_count = self.chat_context.active_channels.len();
            let dm_count = self.chat_context.active_dms.len();
            
            println!("\n╭─── Connection Status ───╮");
            println!("│ Peers connected: {:3}    │", peer_count);
            println!("│ Active channels: {:3}    │", channel_count);
            println!("│ Active DMs:      {:3}    │", dm_count);
            println!("│                         │");
            println!("│ Your nickname: {:^9}│", if self.nickname.len() > 9 { &self.nickname[..9] } else { &self.nickname });
            println!("│ Your ID: {}...│", &self.my_peer_id[..8]);
            println!("╰─────────────────────────╯");
            print!("> ");
            std::io::stdout().flush().unwrap();
            return Ok(true);
        }

        if line == "/exit" {
            let state_to_save = self.create_current_app_state();
            let _ = save_state(&state_to_save);
            return Ok(false);
        }

        if line == "/clear" {
            print!("\x1b[2J\x1b[1;1H");
            // logo reproduction logic could be here or shared
            println!("» Screen cleared");
            print!("> ");
            std::io::stdout().flush().unwrap();
            return Ok(true);
        }

        // Handle /dm command
        if line.starts_with("/dm ") {
            self.handle_dm_command(line).await?;
            return Ok(true);
        }

        // Handle /j or /join command
        if line.starts_with("/j ") || line.starts_with("/join ") {
            self.handle_join_command(line).await?;
            return Ok(true);
        }

        // Handle unknown command
        if line.starts_with('/') {
            println!("\x1b[93m⚠ Unknown command: {}\x1b[0m", line.split_whitespace().next().unwrap_or(""));
            println!("\x1b[90mType /help to see available commands.\x1b[0m");
            return Ok(true);
        }

        // Default: treat as message
        self.send_message(line).await?;
        Ok(true)
    }

    fn create_current_app_state(&self) -> AppState {
        create_app_state(
            self.blocked_peers,
            self.channel_creators,
            &self.chat_context.active_channels,
            self.password_protected_channels,
            self.channel_key_commitments,
            &self.app_state.encrypted_channel_passwords,
            self.nickname,
            self.app_state.identity_key.clone(),
            &self.app_state.favorites
        )
    }

    async fn handle_dm_command(&mut self, line: &str) -> Result<(), Box<dyn std::error::Error>> {
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            println!("\x1b[93m⚠ Usage: /dm <nickname> [message]\x1b[0m");
            return Ok(());
        }
        
        let target_nickname = parts[1];
        let peer_id = {
            let peers = self.peers.lock().unwrap();
            peers.iter()
                .find(|(_, peer)| peer.nickname.as_deref() == Some(target_nickname))
                .map(|(id, _)| id.clone())
        };

        if let Some(target_peer_id) = peer_id {
            if parts.len() == 2 {
                self.chat_context.enter_dm_mode(target_nickname, &target_peer_id);
                debug_println!("{}", self.chat_context.get_status_line());
            } else {
                self.send_private_message(target_nickname, &target_peer_id, parts[2]).await?;
            }
        } else {
            println!("\x1b[93m⚠ User '{}' not found\x1b[0m", target_nickname);
        }
        Ok(())
    }

    async fn handle_join_command(&mut self, line: &str) -> Result<(), Box<dyn std::error::Error>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let channel_name = parts.get(1).unwrap_or(&"").to_string();
        
        if !channel_name.starts_with('#') {
            println!("» Invalid channel name. It must start with #.");
            return Ok(());
        }

        // Basic implementation of join logic
        self.discovered_channels.insert(channel_name.clone());
        self.chat_context.switch_to_channel(&channel_name);
        println!("\x1b[90m» Joined channel: {}\x1b[0m", channel_name);
        print!("> ");
        std::io::stdout().flush().unwrap();
        Ok(())
    }

    async fn send_message(&mut self, line: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Check if in DM mode
        if let ChatMode::PrivateDM { nickname: target_nickname, peer_id: target_peer_id } = &self.chat_context.current_mode {
            let target_nickname = target_nickname.clone();
            let target_peer_id = target_peer_id.clone();
            return self.send_private_message(&target_nickname, &target_peer_id, line).await;
        }

        let current_channel = self.chat_context.current_mode.get_channel().map(|s| s.to_string());
        
        let (message_payload, message_id) = if let Some(ref channel) = current_channel {
            if let Some(channel_key) = self.channel_keys.get(channel) {
                create_encrypted_channel_message_payload(self.nickname, line, channel, channel_key, self.encryption_service, self.my_peer_id)
            } else {
                let payload = create_bitchat_message_payload(self.nickname, line, current_channel.as_deref());
                (payload, Uuid::new_v4().to_string())
            }
        } else {
            let payload = create_bitchat_message_payload(self.nickname, line, current_channel.as_deref());
            (payload, Uuid::new_v4().to_string())
        };

        self.delivery_tracker.track_message(message_id.clone(), line.to_string(), false);
        let signature = self.encryption_service.sign(&message_payload);
        let message_packet = create_bitchat_packet_with_signature(self.my_peer_id, MessageType::Message, message_payload, Some(signature));

        if should_fragment(&message_packet) {
            send_packet_with_fragmentation(self.peripheral, self.cmd_char, message_packet, self.my_peer_id).await?;
        } else {
            let write_type = if message_packet.len() > 512 { WriteType::WithResponse } else { WriteType::WithoutResponse };
            self.peripheral.write(self.cmd_char, &message_packet, write_type).await?;
        }

        let display = format_message_display(MessageDisplayConfig {
            timestamp: chrono::Local::now(),
            sender: self.nickname,
            content: line,
            is_private: false,
            is_channel: current_channel.is_some(),
            channel_name: current_channel.as_deref(),
            recipient: None,
            my_nickname: self.nickname,
        });
        print!("\x1b[1A\r\x1b[K{}\n", display);
        std::io::stdout().flush().unwrap();
        Ok(())
    }

    async fn send_private_message(&mut self, target_nickname: &str, target_peer_id: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        let (message_payload, message_id) = create_bitchat_message_payload_full(self.nickname, message, None, true, self.my_peer_id);
        self.delivery_tracker.track_message(message_id, message.to_string(), true);

        // Encryption logic...
        match self.encryption_service.encrypt(message_payload.as_slice(), target_peer_id) {
            Ok(encrypted) => {
                let signature = self.encryption_service.sign(&encrypted);
                let packet = create_bitchat_packet_with_recipient_and_signature(
                    self.my_peer_id, target_peer_id, MessageType::Message, encrypted, Some(signature)
                );
                send_packet_with_fragmentation(self.peripheral, self.cmd_char, packet, self.my_peer_id).await?;
                
                let display = format_message_display(MessageDisplayConfig {
                    timestamp: chrono::Local::now(),
                    sender: self.nickname,
                    content: message,
                    is_private: true,
                    is_channel: false,
                    channel_name: None,
                    recipient: Some(target_nickname),
                    my_nickname: self.nickname,
                });
                print!("\x1b[1A\r\x1b[K{}\n", display);
                std::io::stdout().flush().unwrap();
            },
            Err(e) => println!("[!] Encryption failed: {:?}", e),
        }
        Ok(())
    }
}
