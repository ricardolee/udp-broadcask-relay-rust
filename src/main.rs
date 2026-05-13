use anyhow::{Context, Result};
use clap::Parser;
use ipnet::IpNet;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Unique ID for the instance (1-63), used for DSCP marking to prevent loops
    #[arg(short, long)]
    id: u8,

    /// UDP port to listen on and relay
    #[arg(short, long)]
    port: u16,

    /// Network interfaces to include in the relay (e.g., eth0, eth1)
    #[arg(short, long)]
    dev: Vec<String>,

    /// Join a specific multicast group (e.g., 224.0.0.251)
    #[arg(short, long)]
    multicast: Vec<Ipv4Addr>,

    /// Allow CIDR for source IP filtering
    #[arg(long)]
    allow_cidr: Vec<IpNet>,

    /// Block CIDR for source IP filtering
    #[arg(long)]
    block_cidr: Vec<IpNet>,

    /// Spoof source IP
    #[arg(short, long)]
    spoof: Option<Ipv4Addr>,

    /// Debug level (use multiple times for more detail)
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,
}

struct InterfaceInfo {
    iface: NetworkInterface,
    send_sock: Socket,
}

fn create_send_socket(iface_name: &str) -> Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::from(255)))
        .context("Failed to create raw socket")?;
    
    sock.set_nonblocking(true)?;
    
    let optval: libc::c_int = 1;
    unsafe {
        if libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0 {
            anyhow::bail!("Failed to set IP_HDRINCL");
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        let iface_bytes = iface_name.as_bytes();
        unsafe {
            if libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface_bytes.as_ptr() as *const libc::c_void,
                iface_bytes.len() as libc::socklen_t,
            ) != 0 {
                anyhow::bail!("Failed to bind to device {}", iface_name);
            }
        }
    }

    Ok(sock)
}

fn main() -> Result<()> {
    let args = Arc::new(Args::parse());

    let env = match args.debug {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(env)).init();

    if args.id == 0 || args.id > 63 {
        anyhow::bail!("ID must be between 1 and 63");
    }

    if args.dev.len() < 2 {
        anyhow::bail!("At least two interfaces must be specified with --dev");
    }

    let all_interfaces = datalink::interfaces();
    let mut interfaces = HashMap::new();

    for dev_name in &args.dev {
        let iface = all_interfaces.iter()
            .find(|i| i.name == *dev_name)
            .with_context(|| format!("Interface {} not found", dev_name))?;
        
        let send_sock = create_send_socket(&iface.name)?;
        interfaces.insert(iface.index, InterfaceInfo {
            iface: iface.clone(),
            send_sock,
        });
    }

    let interfaces = Arc::new(interfaces);

    // Join multicast groups on a dummy socket to ensure the kernel receives them
    let dummy_sock = Socket::new(Domain::IPV4, Type::from(libc::SOCK_DGRAM), Some(Protocol::from(libc::IPPROTO_UDP)))?;
    for mc_addr in &args.multicast {
        for info in interfaces.values() {
            if let Some(ip) = info.iface.ips.iter().find(|ip| ip.is_ipv4()).map(|ip| ip.ip()) {
                if let IpAddr::V4(v4) = ip {
                    let _ = dummy_sock.join_multicast_v4(mc_addr, &v4);
                }
            }
        }
    }

    log::info!("UDP broadcast relay starting (ID: {}, Port: {})", args.id, args.port);

    let mut threads = Vec::new();

    for (&ifindex, _info) in interfaces.iter() {
        let args = Arc::clone(&args);
        let interfaces = Arc::clone(&interfaces);
        
        threads.push(thread::spawn(move || {
            let iface = &interfaces[&ifindex].iface;
            let (_, mut rx) = match datalink::channel(iface, Default::default()) {
                Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                _ => {
                    log::error!("Failed to create datalink channel for {}", iface.name);
                    return;
                }
            };

            log::info!("Listening on {}", iface.name);

            loop {
                let packet = match rx.next() {
                    Ok(packet) => packet,
                    Err(e) => {
                        log::error!("Error receiving on {}: {}", iface.name, e);
                        continue;
                    }
                };

                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                            if ip.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                                if let Some(udp) = UdpPacket::new(ip.payload()) {
                                    if udp.get_destination() == args.port {
                                        // Potential packet for relay
                                        process_packet(&args, &interfaces, ifindex, &ip, &udp);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }));
    }

    for t in threads {
        t.join().unwrap();
    }

    Ok(())
}

fn process_packet(
    args: &Args,
    interfaces: &HashMap<u32, InterfaceInfo>,
    src_ifindex: u32,
    ip: &Ipv4Packet,
    udp: &UdpPacket,
) {
    let dscp = ip.get_dscp();
    if dscp == args.id {
        return;
    }

    let src_ip = ip.get_source();
    let dst_ip = ip.get_destination();

    // Check CIDR filters
    let src_ip_addr = IpAddr::V4(src_ip);
    if !args.allow_cidr.is_empty() {
        if !args.allow_cidr.iter().any(|net| net.contains(&src_ip_addr)) {
            return;
        }
    }
    if args.block_cidr.iter().any(|net| net.contains(&src_ip_addr)) {
        return;
    }

    log::debug!(
        "Relaying packet from {} to {} on port {} (from iface {})",
        src_ip, dst_ip, udp.get_destination(), src_ifindex
    );

    if let Err(e) = relay_packet(args, interfaces, src_ifindex, src_ip, udp.get_source(), dst_ip, udp.payload()) {
        log::error!("Relay error: {}", e);
    }
}

fn relay_packet(
    args: &Args,
    interfaces: &HashMap<u32, InterfaceInfo>,
    src_ifindex: u32,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    data: &[u8],
) -> Result<()> {
    let dscp = args.id;

    let total_len = 20 + 8 + data.len();
    let mut packet_buf = vec![0u8; total_len];

    // IPv4 Header
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet_buf[0..20]).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_dscp(dscp);
        ip_header.set_total_length(total_len as u16);
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(args.spoof.unwrap_or(src_ip));
        ip_header.set_destination(dst_ip);
        ip_header.set_flags(Ipv4Flags::DontFragment);
        
        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    // UDP Header
    {
        let mut udp_header = MutableUdpPacket::new(&mut packet_buf[20..28]).unwrap();
        udp_header.set_source(src_port);
        udp_header.set_destination(args.port);
        udp_header.set_length(8 + data.len() as u16);
        udp_header.set_payload(data);

        let checksum = udp::ipv4_checksum(&udp_header.to_immutable(), &args.spoof.unwrap_or(src_ip), &dst_ip);
        udp_header.set_checksum(checksum);
    }

    let dest_addr = SocketAddrV4::new(dst_ip, args.port);

    for (&ifindex, info) in interfaces {
        if ifindex == src_ifindex {
            continue;
        }

        log::trace!("Sending packet out of {}", info.iface.name);
        match info.send_sock.send_to(&packet_buf, &dest_addr.into()) {
            Ok(_) => (),
            Err(e) => log::warn!("Failed to send on {}: {}", info.iface.name, e),
        }
    }

    Ok(())
}
