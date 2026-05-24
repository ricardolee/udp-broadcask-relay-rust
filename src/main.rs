use anyhow::{Context, Result};
use clap::Parser;
use ipnet::IpNet;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::thread;

/// CLI Arguments structure.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Unique ID for the instance (1-63), used in the IPv4 DSCP field to prevent forwarding loops.
    #[arg(short, long)]
    id: u8,

    /// UDP port to listen on and relay.
    #[arg(short, long)]
    port: u16,

    /// Network interfaces to include in the relay (e.g., eth0, eth1).
    #[arg(short, long)]
    dev: Vec<String>,

    /// Join specific multicast groups (e.g., 224.0.0.251) to ensure the kernel receives them.
    #[arg(short, long)]
    multicast: Vec<Ipv4Addr>,

    /// Allow CIDR range for source IP filtering (allowlist).
    #[arg(long)]
    allow_cidr: Vec<IpNet>,

    /// Block CIDR range for source IP filtering (blocklist).
    #[arg(long)]
    block_cidr: Vec<IpNet>,

    /// Spoof source IP. If specified, the outgoing packet's source IP is replaced with this IP.
    #[arg(short, long)]
    spoof: Option<Ipv4Addr>,

    /// Debug level (use multiple times for more details, e.g., -vv).
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    debug: u8,
}

/// Stores runtime information required for each participating network interface.
struct InterfaceInfo {
    /// The network interface entity identified by pnet.
    iface: NetworkInterface,
    /// Dedicated raw socket used to transmit custom IP packets out of this interface.
    send_sock: Socket,
}

/// Creates a raw socket bound to a specific network interface.
fn create_send_socket(iface_name: &str) -> Result<Socket> {
    // Create an IPv4 raw socket using protocol 255 (raw IP protocol).
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(255)))
        .context("Failed to create raw socket")?;
    
    sock.set_nonblocking(true)?;
    sock.set_broadcast(true)?;
    
    // Enable IP_HDRINCL to allow us to supply our own fully custom IPv4 header.
    sock.set_header_included_v4(true)?;
    
    // Bind to the physical network interface on Linux to ensure egress through the correct path.
    #[cfg(target_os = "linux")]
    {
        sock.bind_device(Some(iface_name.as_bytes()))?;
    }

    Ok(sock)
}

fn main() -> Result<()> {
    let args = Arc::new(Args::parse());

    // Dynamically configure log filtering level based on debug verbosity count.
    let env = match args.debug {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(env)).init();

    // The DSCP value must be a valid 6-bit identifier (1 to 63).
    if args.id == 0 || args.id > 63 {
        anyhow::bail!("ID must be between 1 and 63");
    }

    let all_interfaces = datalink::interfaces();
    let mut interfaces = HashMap::new();

    // Find and initialize the configured network interfaces.
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

    // A minimum of two distinct interfaces is required to perform relaying.
    if interfaces.len() < 2 {
        anyhow::bail!("At least two unique interfaces must be specified");
    }

    let interfaces = Arc::new(interfaces);

    // Join multicast groups on a dummy UDP socket to trigger IGMP reports.
    // This informs upstream switches/routers to forward multicast frames to these interfaces.
    let dummy_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
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

    // Spawn a worker thread for each interface to capture raw incoming ethernet packets.
    for (&ifindex, _info) in interfaces.iter() {
        let args = Arc::clone(&args);
        let interfaces = Arc::clone(&interfaces);
        
        threads.push(thread::spawn(move || {
            let iface = &interfaces[&ifindex].iface;
            
            // Listen for incoming Ethernet packets on the data link layer.
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

                // Parse packet layer-by-layer: Ethernet -> IPv4 -> UDP
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                            if ip.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                                if let Some(udp) = UdpPacket::new(ip.payload()) {
                                    // Process the packet only if it targets the monitored UDP port.
                                    if udp.get_destination() == args.port {
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

/// Evaluates whether a captured UDP packet should be relayed.
fn process_packet(
    args: &Args,
    interfaces: &HashMap<u32, InterfaceInfo>,
    src_ifindex: u32,
    ip: &Ipv4Packet,
    udp: &UdpPacket,
) {
    // Loop Prevention Mechanism:
    // If the incoming packet's DSCP matches our instance ID, it means the packet
    // was already relayed by us on another interface. Drop it to prevent loops.
    let dscp = ip.get_dscp();
    if dscp == args.id {
        return;
    }

    let src_ip = ip.get_source();
    let dst_ip = ip.get_destination();

    // Apply CIDR network filter rules (Allowlist / Blocklist).
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

/// Construct and send a newly formatted raw IP packet out of target interfaces.
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

    // Buffer allocation (IPv4 header: 20 bytes + UDP header: 8 bytes + payload)
    let total_len = 20 + 8 + data.len();
    let mut packet_buf = vec![0u8; total_len];

    // Assemble the IPv4 Header
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet_buf).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5); // 5 * 32bit words = 20 bytes
        ip_header.set_dscp(dscp);       // Mark packet with our unique ID for loop prevention
        ip_header.set_total_length(total_len as u16);
        ip_header.set_ttl(64);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        // Use spoof IP if specified, otherwise keep the original sender's IP
        let source_ip = args.spoof.unwrap_or(src_ip);
        ip_header.set_source(source_ip);
        ip_header.set_destination(dst_ip);
        ip_header.set_flags(Ipv4Flags::DontFragment);

        // Assemble the UDP Header
        {
            let mut udp_header = MutableUdpPacket::new(ip_header.payload_mut()).unwrap();
            udp_header.set_source(src_port);
            udp_header.set_destination(args.port);
            udp_header.set_length(8 + data.len() as u16);
            udp_header.set_payload(data);

            // Calculate UDP checksum with pseudo-header
            let checksum = udp::ipv4_checksum(&udp_header.to_immutable(), &source_ip, &dst_ip);
            udp_header.set_checksum(checksum);
        }
        
        // Calculate IPv4 Header checksum
        let checksum = pnet::packet::ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
    }

    let dest_addr = SocketAddrV4::new(dst_ip, args.port);

    // Broadcast the custom raw packet out of all interfaces except the one it arrived on
    for (&ifindex, info) in interfaces {
        if ifindex == src_ifindex {
            continue; // Prevent reflecting packets back to the source network
        }

        log::trace!("Sending packet out of {}", info.iface.name);
        
        // Send raw IP packet directly (IP_HDRINCL ensures our custom headers are kept)
        match info.send_sock.send_to(&packet_buf, &dest_addr.into()) {
            Ok(_) => (),
            Err(e) => log::warn!("Failed to send on {}: {}", info.iface.name, e),
        }
    }

    Ok(())
}
