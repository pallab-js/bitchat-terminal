use btleplug::api::{Central, Characteristic, Manager as _, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use tokio::time::{self, Duration};
use rand::Rng;
use std::cmp;
use crate::debug_println;
use crate::protocol::{
    BITCHAT_SERVICE_UUID, MessageType,
    create_bitchat_packet
};

pub async fn find_peripheral(adapter: &btleplug::platform::Adapter) -> Result<Option<Peripheral>, btleplug::Error> {
    for p in adapter.peripherals().await? {
        if let Ok(Some(properties)) = p.properties().await {
            if properties.services.contains(&BITCHAT_SERVICE_UUID) { return Ok(Some(p)); }
        }
    }
    Ok(None)
}

pub async fn send_packet_with_fragmentation(
    peripheral: &Peripheral,
    cmd_char: &Characteristic,
    packet: Vec<u8>,
    my_peer_id: &str
) -> Result<(), Box<dyn std::error::Error>> {
    // Swift's logic: if packet > 500 bytes, fragment it
    if packet.len() > 500 {
        println!("[FRAG] ==================== FRAGMENTATION START ====================");
        println!("[FRAG] Original packet size: {} bytes", packet.len());
        
        let fragment_size = 150; // Conservative size for iOS BLE compatibility
        let chunks: Vec<&[u8]> = packet.chunks(fragment_size).collect();
        let total_fragments = chunks.len() as u16;
        
        let mut fragment_id = [0u8; 8];
        rand::thread_rng().fill(&mut fragment_id);
        
        for (index, chunk) in chunks.iter().enumerate() {
            let fragment_type = match index {
                0 => MessageType::FragmentStart,
                n if n == chunks.len() - 1 => MessageType::FragmentEnd,
                _ => MessageType::FragmentContinue,
            };
            
            let mut fragment_payload = Vec::new();
            fragment_payload.extend_from_slice(&fragment_id);
            
            let index_bytes = [(index as u16 >> 8) as u8, (index as u16 & 0xFF) as u8];
            let total_bytes = [(total_fragments >> 8) as u8, (total_fragments & 0xFF) as u8];
            
            fragment_payload.push(index_bytes[0]);
            fragment_payload.push(index_bytes[1]);
            fragment_payload.push(total_bytes[0]);
            fragment_payload.push(total_bytes[1]);
            fragment_payload.push(MessageType::Message as u8);
            fragment_payload.extend_from_slice(chunk);
            
            let fragment_packet = create_bitchat_packet(
                my_peer_id,
                fragment_type,
                fragment_payload
            );
            
            if peripheral.write(cmd_char, &fragment_packet, WriteType::WithoutResponse).await.is_err() {
                return Err(format!("Failed to send fragment {}/{} (size: {} bytes)", index + 1, total_fragments, fragment_packet.len()).into());
            }
            
            if index < chunks.len() - 1 {
                time::sleep(Duration::from_millis(20)).await;
            }
        }
        
        println!("[FRAG] ✓ Successfully sent {} fragments", total_fragments);
        Ok(())
    } else {
        let write_type = if packet.len() > 512 {
            WriteType::WithResponse
        } else {
            WriteType::WithoutResponse
        };
        
        if peripheral.write(cmd_char, &packet, write_type).await.is_err() {
            return Err(format!("Failed to send {} byte packet", packet.len()).into());
        }
        
        Ok(())
    }
}

pub async fn send_channel_announce(
    peripheral: &Peripheral,
    cmd_char: &Characteristic,
    my_peer_id: &str,
    channel: &str,
    is_protected: bool,
    key_commitment: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let protected_str = if is_protected { "1" } else { "0" };
    let payload = format!(
        "{}|{}|{}|{}",
        channel,
        protected_str,
        my_peer_id,
        key_commitment.unwrap_or("")
    );
    
    let packet = create_bitchat_packet(
        my_peer_id,
        MessageType::ChannelAnnounce,
        payload.into_bytes()
    );
    
    let mut packet_with_ttl = packet;
    packet_with_ttl[2] = 5; // TTL is at offset 2
    
    debug_println!("[CHANNEL] Sending channel announce for {}", channel);
    send_packet_with_fragmentation(peripheral, cmd_char, packet_with_ttl, my_peer_id).await
}
