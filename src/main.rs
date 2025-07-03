extern crate termion;

use termion::color;
use pcap::Device;
use figlet_rs::FIGfont;
use std::thread::{sleep, spawn};
use std::time::Duration;
use etherparse::{SlicedPacket, PacketBuilder, ArpPacket, EtherType, ArpHardwareId, ArpOperation};
use std::io::{stdout, Write};
use crossterm::{
    style::{Color, Print, ResetColor, SetForegroundColor},
    ExecutableCommand,
};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use local_ip_address::local_ip;
use crossterm::cursor;
use regex::Regex;

fn extract_mac_addresses(text: &str) -> Option<(String, String)> {
    let re = Regex::new(r"source: \[(\d+, \d+, \d+, \d+, \d+, \d+)\], destination: \[(\d+, \d+, \d+, \d+, \d+, \d+)\]").ok()?;
    let captures = re.captures(text)?;

    let src_str = captures.get(1)?.as_str();
    let dst_str = captures.get(2)?.as_str();

    let src_mac = format_mac(src_str)?;
    let dst_mac = format_mac(dst_str)?;

    Some((src_mac, dst_mac))
}

fn format_mac(numbers: &str) -> Option<String> {
    let bytes: Vec<&str> = numbers.split(", ").collect();
    if bytes.len() != 6 {
        return None;
    }

    let mac = bytes.iter()
        .map(|b| Some(format!("{:02X}", b.parse::<u8>().ok()?)))
        .collect::<Option<Vec<String>>>()?
        .join(":");

    Some(mac)
}

fn show_waiting_animation(task: &str, duration_secs: u64) {
    use std::time::Instant;

    let spinner_chars = ['|', '/', '-', '\\'];
    let mut index = 0;
    let start_time = Instant::now();
    let total_duration = Duration::from_secs(duration_secs);
    let mut stdout = stdout();

    stdout.execute(cursor::Hide).unwrap();
    stdout.execute(SetForegroundColor(Color::Green)).unwrap();
    print!("{} ", task);
    stdout.flush().unwrap();

    while Instant::now() - start_time < total_duration {
        print!("\r{} {} ", task, spinner_chars[index]);
        stdout.flush().unwrap();
        index = (index + 1) % spinner_chars.len();
        sleep(Duration::from_millis(100));
    }

    stdout.execute(cursor::Show).unwrap();
    stdout.execute(ResetColor).unwrap();
    println!("\r{} ✓ Complete", task);
}

fn arpSpoofing() {
    let builder = PacketBuilder::
        ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
        .arp(ArpPacket::new(
            ArpHardwareId::ETHERNET,
            EtherType::IPV4,
            ArpOperation::REQUEST,
            &[1, 2, 3, 4, 5, 6],
            &[7, 6, 8, 9],
            &[10, 11, 12, 14, 15, 16],
            &[17, 18, 19, 20]
        ).unwrap());

    let mut result = Vec::<u8>::with_capacity(builder.size());
    builder.write(&mut result).unwrap();
    println!("ARP Packet Built: {:?}", result);
}

fn networkScanning() {
    let mut listMac = Vec::new();

    let device = Device::lookup()
        .expect("Failed to get default device")
        .expect("No device found");

    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .promisc(true) // Promiscuous mode to see all traffic
        .immediate_mode(true)
        .open()
        .unwrap();


    loop {
        let packet_received = Arc::new(AtomicBool::new(false));
        let packet_received_clone = packet_received.clone();

        let animation_thread = spawn(move || {
            let spinner_chars = ['|', '/', '-', '\\'];
            let mut index = 0;
            let mut stdout = stdout();

            stdout.execute(cursor::Hide).unwrap();
            stdout.execute(SetForegroundColor(Color::Yellow)).unwrap();
            stdout.flush().unwrap();

            while !packet_received_clone.load(Ordering::Relaxed) {
                print!("\rWaiting for network packets... {}", spinner_chars[index]);
                stdout.flush().unwrap();
                index = (index + 1) % spinner_chars.len();
                sleep(Duration::from_millis(100));
            }

            stdout.execute(ResetColor).unwrap();
            stdout.execute(cursor::Show).unwrap();
        });

        match cap.next_packet() {
            Ok(packet) => {
                packet_received.store(true, Ordering::Relaxed);
                animation_thread.join().unwrap();

                match SlicedPacket::from_ethernet(&packet) {
                    Err(e) => eprintln!("{}Error parsing packet: {:?}{}", color::Fg(color::Red), e, color::Fg(color::Reset)),
                    Ok(packet) => {
                        println!("{}== PACKET ======================={}", color::Fg(color::Cyan), color::Fg(color::Reset));
                         let packet_string = format!("{:?}", packet.link);

                        match extract_mac_addresses(&packet_string) {
                            Some((src, dst)) => {
                                println!("Source MAC: {}\n", src);
                                println!("Destination MAC: {}\n", dst);
                                if !listMac.contains(&src){
                                    listMac.push(src);
                                }
                                if !listMac.contains(&dst){
                                    listMac.push(dst);
                                }

                                
                            },
                            None => println!("Failed to extract MAC addresses."),
                        }

                        println!("Link: {:?}\n", packet.link);
                        println!("LinkExts: {:?}\n", packet.link_exts);
                        println!("Network: {:?}\n", packet.net);
                        println!("Transport: {:?}\n", packet.transport);
                        println!("{}================================={}\n", color::Fg(color::Cyan), color::Fg(color::Reset));
                    }
                }
            }

            Err(e) => {
                packet_received.store(true, Ordering::Relaxed);
                animation_thread.join().unwrap();
                eprintln!("Error receiving packet: {}", e);
                break;
            }
        }
        sleep(Duration::from_millis(2000));
    }
}

fn main() -> std::io::Result<()> {
    let my_local_ip = local_ip();
    let standard_font = FIGfont::standard().unwrap();
    if let Some(figure) = standard_font.convert("ANTIELECTROPHILE") {
        stdout()
            .execute(SetForegroundColor(Color::Blue))?
            .execute(Print(figure.to_string()))?;
    }

    networkScanning();

    let running: bool = true;

    while running {
        unimplemented!();
    }

    show_waiting_animation("Starting network scanner", 3);

    println!("Local IP: {:?}", my_local_ip);

    Ok(())
}
