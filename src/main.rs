use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ipnet::IpNet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::MutablePacket;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Unique instance ID offset for TTL-based loop prevention.
const TTL_ID_OFFSET: u8 = 64;

/// CLI Arguments structure.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Unique ID for the instance (1-63), used in loop prevention.
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

    /// Spoof source IP. If specified, the outgoing packet's source IP is replaced.
    /// Can be literal IP or special "1.1.1.1" / "1.1.1.2".
    #[arg(short, long)]
    spoof: Option<String>,

    /// TTL-based loop prevention instead of ToS/DSCP loop prevention.
    #[arg(short = 't', long)]
    ttl_id: bool,

    /// Discard packets matching specific other relay instance IDs.
    #[arg(long)]
    blockid: Vec<u8>,

    /// Enable SSDP M-SEARCH requests processing.
    /// Format: --msearch <action>[,<search_string>]
    /// action: fwd, block, proxy, dial
    #[arg(long)]
    msearch: Vec<String>,

    /// Debug level (use multiple times for more details, e.g., -vv).
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    debug: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AclAction {
    Allow,
    Block,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AclRule {
    net: IpNet,
    action: AclAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MsearchAction {
    Forward,
    Block,
    Proxy,
    Dial,
}

#[derive(Clone, Debug)]
struct MsearchFilter {
    search_string: String,
    action: MsearchAction,
}

/// Stores runtime information required for each participating network interface.
struct InterfaceInfo {
    /// The network interface entity.
    iface: NetworkInterface,
    /// Dedicated raw socket used to transmit custom IP packets out of this interface.
    send_sock: Socket,
}

struct MsearchProxyInfo {
    sock: UdpSocket,
    client_addr: SocketAddrV4,
    src_ifindex: u32,
    action: MsearchAction,
    last_active: Instant,
}

struct TcpProxyListenerInfo {
    listener: TcpListener,
    target_addr: SocketAddrV4,
    client_facing_ip: Ipv4Addr,
    last_active: Instant,
}

struct TcpProxyConnection {
    client: TcpStream,
    server: TcpStream,
    client_fd: RawFd,
    server_fd: RawFd,
    target_addr: SocketAddrV4,
    client_facing_ip: Ipv4Addr,
    last_active: Instant,
}

#[derive(Debug, Clone, Copy)]
enum FdRole {
    MainUdp,
    MsearchProxy { port: u16 },
    TcpListener { port: u16 },
    TcpClient { conn_index: usize },
    TcpServer { conn_index: usize },
}

/// Creates a raw socket bound to a specific network interface.
fn create_send_socket(iface_name: &str) -> Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(255)))
        .context("Failed to create raw socket")?;

    sock.set_nonblocking(true)?;
    sock.set_broadcast(true)?;
    sock.set_header_included_v4(true)?;

    #[cfg(target_os = "linux")]
    {
        sock.bind_device(Some(iface_name.as_bytes()))?;
    }

    #[cfg(target_os = "freebsd")]
    {
        let all_interfaces = datalink::interfaces();
        let iface = all_interfaces
            .iter()
            .find(|i| i.name == iface_name)
            .with_context(|| format!("Interface {} not found", iface_name))?;

        let iface_ip = iface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .map(|ip| ip.ip())
            .with_context(|| format!("No IPv4 address on interface {}", iface_name))?;

        if let IpAddr::V4(v4_addr) = iface_ip {
            let bind_addr = SocketAddrV4::new(v4_addr, 0);
            sock.bind(&bind_addr.into())
                .context("Failed to bind raw socket to interface IP on FreeBSD")?;
            sock.set_multicast_if_v4(&v4_addr)
                .context("Failed to set IP_MULTICAST_IF on FreeBSD")?;
        }
    }

    Ok(sock)
}

fn relay_packet(
    args: &Args,
    interfaces: &HashMap<u32, InterfaceInfo>,
    src_ifindex: u32,
    only_ifindex: Option<u32>,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    original_ttl: u8,
    original_tos: u8,
    data: &[u8],
) -> Result<()> {
    for (&ifindex, info) in interfaces.iter() {
        if let Some(target) = only_ifindex {
            if ifindex != target {
                continue;
            }
        } else if ifindex == src_ifindex {
            continue; // Prevent reflecting packets back to the source network
        }

        // Get the egress interface IP address
        let outgoing_iface_ip = info
            .iface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .map(|ip| ip.ip())
            .context("No IPv4 address on egress interface")?;

        let outgoing_iface_ipv4 = match outgoing_iface_ip {
            IpAddr::V4(v4) => v4,
            _ => continue,
        };

        // Determine source IP and source port based on spoof settings
        let (source_ip, source_port) = match &args.spoof {
            Some(s) if s == "1.1.1.1" => (outgoing_iface_ipv4, args.port),
            Some(s) if s == "1.1.1.2" => (outgoing_iface_ipv4, src_port),
            Some(s) => {
                if let Ok(literal_ip) = s.parse::<Ipv4Addr>() {
                    (literal_ip, src_port)
                } else {
                    (src_ip, src_port)
                }
            }
            None => (src_ip, src_port),
        };

        // Determine destination IP
        // If received on interface broadcast address or 255.255.255.255,
        // rewrite to the target interface's broadcast address.
        let outgoing_subnet = info
            .iface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .context("No IPv4 subnet on egress interface")?;

        let ip_u32 = u32::from(outgoing_iface_ipv4);
        let mask_u32 = !((1 << (32 - outgoing_subnet.prefix())) - 1);
        let target_broadcast_ip = Ipv4Addr::from(ip_u32 | !mask_u32);

        let final_dst_ip = if dst_ip == Ipv4Addr::new(255, 255, 255, 255) {
            target_broadcast_ip
        } else {
            // Check if dst_ip is the broadcast IP of the source interface
            let src_iface_info = interfaces.get(&src_ifindex);
            let is_src_broadcast = if let Some(src_info) = src_iface_info {
                if let Some(src_subnet) = src_info.iface.ips.iter().find(|ip| ip.is_ipv4()) {
                    if let IpAddr::V4(src_iface_ipv4) = src_subnet.ip() {
                        let src_ip_u32 = u32::from(src_iface_ipv4);
                        let src_mask_u32 = !((1 << (32 - src_subnet.prefix())) - 1);
                        dst_ip == Ipv4Addr::from(src_ip_u32 | !src_mask_u32)
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };

            if is_src_broadcast {
                target_broadcast_ip
            } else {
                dst_ip
            }
        };

        // Determine TTL and ToS for loop prevention
        let (outgoing_ttl, outgoing_dscp, outgoing_ecn) = if args.ttl_id {
            (
                args.id + TTL_ID_OFFSET,
                original_tos >> 2,
                original_tos & 0x03,
            )
        } else {
            let tos_dscp = args.id;
            let tos_ecn = original_tos & 0x03;
            (original_ttl, tos_dscp, tos_ecn)
        };

        // Buffer allocation (IPv4 header: 20 bytes + UDP header: 8 bytes + payload)
        let total_len = 20 + 8 + data.len();
        let mut packet_buf = vec![0u8; total_len];

        // Assemble the IPv4 Header
        {
            let mut ip_header = MutableIpv4Packet::new(&mut packet_buf).unwrap();
            ip_header.set_version(4);
            ip_header.set_header_length(5); // 5 * 32bit words = 20 bytes
            ip_header.set_dscp(outgoing_dscp);
            ip_header.set_ecn(outgoing_ecn);
            ip_header.set_total_length(total_len as u16);
            ip_header.set_ttl(outgoing_ttl);
            ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_header.set_source(source_ip);
            ip_header.set_destination(final_dst_ip);
            ip_header.set_flags(Ipv4Flags::DontFragment);

            // Assemble the UDP Header
            {
                let mut udp_header = MutableUdpPacket::new(ip_header.payload_mut()).unwrap();
                udp_header.set_source(source_port);
                udp_header.set_destination(dst_port);
                udp_header.set_length(8 + data.len() as u16);
                udp_header.set_payload(data);

                // Set UDP checksum to 0 (no checksum/disabled for raw IP UDP packets)
                udp_header.set_checksum(0);
            }

            // Set IP checksum to 0 (Linux kernel will automatically compute it)
            ip_header.set_checksum(0);
        }

        let dest_addr = SocketAddrV4::new(final_dst_ip, dst_port);
        log::trace!("Sending packet out of {} to {}", info.iface.name, dest_addr);

        match info.send_sock.send_to(&packet_buf, &dest_addr.into()) {
            Ok(_) => (),
            Err(e) => log::warn!("Failed to send on {}: {}", info.iface.name, e),
        }
    }

    Ok(())
}

fn create_rcv_socket(port: u16) -> Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create UDP socket")?;

    sock.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    sock.set_reuse_port(true)?;

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    sock.bind(&addr.into())
        .context("Failed to bind UDP socket")?;
    sock.set_nonblocking(true)?;

    let fd = sock.as_raw_fd();
    unsafe {
        let yes: libc::c_int = 1;

        #[cfg(target_os = "linux")]
        {
            if libc::setsockopt(
                fd,
                libc::SOL_IP,
                libc::IP_PKTINFO,
                &yes as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) < 0
            {
                return Err(anyhow!("Failed to set IP_PKTINFO"));
            }
        }

        #[cfg(target_os = "freebsd")]
        {
            if libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVIF,
                &yes as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) < 0
            {
                return Err(anyhow!("Failed to set IP_RECVIF"));
            }

            if libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_RECVDSTADDR,
                &yes as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) < 0
            {
                return Err(anyhow!("Failed to set IP_RECVDSTADDR"));
            }
        }

        if libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_RECVTTL,
            &yes as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) < 0
        {
            return Err(anyhow!("Failed to set IP_RECVTTL"));
        }

        if libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_RECVTOS,
            &yes as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) < 0
        {
            return Err(anyhow!("Failed to set IP_RECVTOS"));
        }
    }

    Ok(sock)
}

struct RecvMsgResult {
    len: usize,
    src_addr: SocketAddrV4,
    dst_ip: Ipv4Addr,
    ifindex: u32,
    ttl: u8,
    tos: u8,
}

fn recv_with_ancillary(fd: RawFd, buf: &mut [u8]) -> Result<Option<RecvMsgResult>> {
    let mut src_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut control_buf = [0u8; 4096];
    let mut msg: libc::msghdr = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_buf.len() as _;
    msg.msg_flags = 0;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(err).context("recvmsg failed");
    }

    let len = n as usize;
    let src_port = u16::from_be(src_addr.sin_port);
    let src_ip = Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
    let src_socket_addr = SocketAddrV4::new(src_ip, src_port);

    let mut dst_ip = Ipv4Addr::UNSPECIFIED;
    let mut ifindex = 0;
    let mut ttl = 0u8;
    let mut tos = 0u8;

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_IP || (*cmsg).cmsg_level == libc::IPPROTO_IP {
                if (*cmsg).cmsg_type == libc::IP_TTL {
                    let ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                    ttl = *ptr as u8;
                } else if (*cmsg).cmsg_type == libc::IP_TOS {
                    let ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                    tos = *ptr as u8;
                } else {
                    #[cfg(target_os = "linux")]
                    {
                        if (*cmsg).cmsg_type == libc::IP_PKTINFO {
                            let ptr = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                            let pktinfo = *ptr;
                            ifindex = pktinfo.ipi_ifindex as u32;
                            dst_ip = Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr));
                        }
                    }
                    #[cfg(target_os = "freebsd")]
                    {
                        if (*cmsg).cmsg_type == libc::IP_RECVIF {
                            let sdl = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_dl);
                            ifindex = sdl.sdl_index as u32;
                        } else if (*cmsg).cmsg_type == libc::IP_RECVDSTADDR {
                            let in_addr = &*(libc::CMSG_DATA(cmsg) as *const libc::in_addr);
                            dst_ip = Ipv4Addr::from(u32::from_be(in_addr.s_addr));
                        }
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok(Some(RecvMsgResult {
        len,
        src_addr: src_socket_addr,
        dst_ip,
        ifindex,
        ttl,
        tos,
    }))
}

fn check_cidr_acl(rules: &[AclRule], default_action: AclAction, src_ip: Ipv4Addr) -> bool {
    let src_ip_addr = IpAddr::V4(src_ip);
    for rule in rules {
        if rule.net.contains(&src_ip_addr) {
            return rule.action == AclAction::Allow;
        }
    }
    default_action == AclAction::Allow
}

fn replace_header_value(payload: &[u8], header_name: &str, new_value: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(payload);
    let search_lower = text.to_ascii_lowercase();
    let header_lower = header_name.to_ascii_lowercase();

    if let Some(start_idx) = search_lower.find(&header_lower) {
        if let Some(end_offset) = text[start_idx..].find("\r\n") {
            let end_idx = start_idx + end_offset;
            let new_line = format!("{}: {}", header_name, new_value);

            let mut new_payload = Vec::new();
            new_payload.extend_from_slice(&payload[..start_idx]);
            new_payload.extend_from_slice(new_line.as_bytes());
            new_payload.extend_from_slice(&payload[end_idx..]);
            return new_payload;
        }
    }
    payload.to_vec()
}

fn extract_ip_port_from_header(payload: &[u8], header_name: &str) -> Option<(Ipv4Addr, u16)> {
    let text = String::from_utf8_lossy(payload);
    let search_lower = text.to_ascii_lowercase();
    let header_lower = header_name.to_ascii_lowercase();

    if let Some(start_idx) = search_lower.find(&header_lower) {
        if let Some(end_offset) = text[start_idx..].find("\r\n") {
            let end_idx = start_idx + end_offset;
            let line = &text[start_idx..end_idx];
            let val = line.splitn(2, ':').nth(1)?.trim();
            if let Some(url_start) = val.find("http://") {
                let url_val = &val[url_start + 7..];
                let host_part = url_val.split('/').next()?;
                let mut parts = host_part.splitn(2, ':');
                let host = parts.next()?;
                let port = parts.next().unwrap_or("80").parse::<u16>().unwrap_or(80);
                let ip = host.parse::<Ipv4Addr>().ok()?;
                return Some((ip, port));
            }
        }
    }
    None
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

    // Initialize ACL rules
    let mut acl_rules = Vec::new();
    for net in &args.allow_cidr {
        acl_rules.push(AclRule {
            net: *net,
            action: AclAction::Allow,
        });
    }
    for net in &args.block_cidr {
        acl_rules.push(AclRule {
            net: *net,
            action: AclAction::Block,
        });
    }
    // Sort descending by prefix length (longest prefix match)
    acl_rules.sort_by(|a, b| b.net.prefix_len().cmp(&a.net.prefix_len()));

    let default_acl_action = if !args.allow_cidr.is_empty() {
        AclAction::Block
    } else {
        AclAction::Allow
    };

    // Parse `--msearch` options
    let mut msearch_filters = Vec::new();
    let mut default_msearch_action = MsearchAction::Forward;

    for ms in &args.msearch {
        let parts: Vec<&str> = ms.splitn(2, ',').collect();
        let action_str = parts[0].trim();
        let action = match action_str {
            "fwd" => MsearchAction::Forward,
            "block" => MsearchAction::Block,
            "proxy" => MsearchAction::Proxy,
            "dial" => MsearchAction::Dial,
            _ => anyhow::bail!("Unknown msearch action: {}", action_str),
        };

        if parts.len() == 2 {
            let search_str = parts[1].trim().to_string();
            log::info!(
                "Added M-SEARCH filter: action {:?}, pattern '{}'",
                action,
                search_str
            );
            msearch_filters.push(MsearchFilter {
                search_string: search_str,
                action: action.clone(),
            });
        } else {
            if action == MsearchAction::Dial {
                msearch_filters.push(MsearchFilter {
                    search_string: "urn:dial-multiscreen-org:service:dial:1".to_string(),
                    action: action.clone(),
                });
                log::info!("Added M-SEARCH filter: action {:?}, pattern 'urn:dial-multiscreen-org:service:dial:1'", action);
            } else {
                default_msearch_action = action;
            }
        }
    }
    if args.msearch.is_empty() {
        log::info!("Default M-SEARCH action: {:?}", default_msearch_action);
    } else {
        log::info!(
            "Default M-SEARCH action (fallback): {:?}",
            default_msearch_action
        );
    }

    let all_interfaces = datalink::interfaces();
    let mut interfaces = HashMap::new();

    for dev_name in &args.dev {
        let iface = all_interfaces
            .iter()
            .find(|i| i.name == *dev_name)
            .with_context(|| format!("Interface {} not found", dev_name))?;

        let send_sock = create_send_socket(&iface.name)?;
        interfaces.insert(
            iface.index,
            InterfaceInfo {
                iface: iface.clone(),
                send_sock,
            },
        );
    }

    if interfaces.len() < 2 {
        anyhow::bail!("At least two unique interfaces must be specified");
    }

    let interfaces = Arc::new(interfaces);

    // Join multicast groups on a dummy UDP socket to trigger IGMP reports.
    let dummy_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    for mc_addr in &args.multicast {
        for info in interfaces.values() {
            if let Some(ip) = info
                .iface
                .ips
                .iter()
                .find(|ip| ip.is_ipv4())
                .map(|ip| ip.ip())
            {
                if let IpAddr::V4(v4) = ip {
                    let _ = dummy_sock.join_multicast_v4(mc_addr, &v4);
                }
            }
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);

    ctrlc::set_handler(move || {
        log::info!("Shutdown signal received. Shutting down gracefully...");
        r.store(false, Ordering::SeqCst);
    })
    .context("Error setting Ctrl-C handler")?;

    log::info!(
        "UDP broadcast relay starting (ID: {}, Port: {})",
        args.id,
        args.port
    );

    // Create main receive socket
    let rcv_sock = create_rcv_socket(args.port)?;
    let main_fd = rcv_sock.as_raw_fd();

    // Join multicast groups on the main socket to ensure the OS kernel delivers them to us
    for mc_addr in &args.multicast {
        for info in interfaces.values() {
            if let Some(ip) = info
                .iface
                .ips
                .iter()
                .find(|ip| ip.is_ipv4())
                .map(|ip| ip.ip())
            {
                if let IpAddr::V4(v4) = ip {
                    if let Err(e) = rcv_sock.join_multicast_v4(mc_addr, &v4) {
                        log::warn!(
                            "Failed to join multicast group {} on interface {}: {}",
                            mc_addr,
                            info.iface.name,
                            e
                        );
                    } else {
                        log::info!(
                            "Joined multicast group {} on interface {}",
                            mc_addr,
                            info.iface.name
                        );
                    }
                }
            }
        }
    }

    // Map to hold dynamic M-SEARCH proxies
    let mut msearch_proxies: HashMap<u16, MsearchProxyInfo> = HashMap::new();
    // Map to hold dynamic TCP REST/DIAL proxies
    let mut tcp_proxies: HashMap<u16, TcpProxyListenerInfo> = HashMap::new();

    let mut buf = vec![0u8; 65536];
    let mut active_tcp_connections: Vec<TcpProxyConnection> = Vec::new();
    let mut last_gc_time = Instant::now();

    while running.load(Ordering::SeqCst) {
        // Inline Garbage Collector (runs every 5 seconds)
        let now = Instant::now();
        if now.duration_since(last_gc_time) >= Duration::from_secs(5) {
            last_gc_time = now;

            // Clean UDP M-SEARCH proxies (expire after 60s)
            msearch_proxies.retain(|&port, p| {
                if now.duration_since(p.last_active) > Duration::from_secs(60) {
                    log::info!("Expiring M-SEARCH proxy on port {}", port);
                    false
                } else {
                    true
                }
            });

            // Clean TCP REST proxies (expire after 120s)
            tcp_proxies.retain(|&port, p| {
                if now.duration_since(p.last_active) > Duration::from_secs(120) {
                    log::info!("Expiring REST TCP proxy on port {}", port);
                    false
                } else {
                    true
                }
            });

            // Clean inactive active TCP proxy connections (expire after 120s)
            active_tcp_connections.retain(|conn| {
                if now.duration_since(conn.last_active) > Duration::from_secs(120) {
                    log::info!("Expiring active TCP proxy connection due to inactivity");
                    false
                } else {
                    true
                }
            });
        }

        // Build pollfd array
        let mut poll_fds = Vec::new();
        let mut fd_roles = Vec::new();

        // 1. Main receive UDP socket
        poll_fds.push(libc::pollfd {
            fd: main_fd,
            events: libc::POLLIN,
            revents: 0,
        });
        fd_roles.push(FdRole::MainUdp);

        // 2. Active UDP M-SEARCH proxy sockets
        for (&port, p) in &msearch_proxies {
            poll_fds.push(libc::pollfd {
                fd: p.sock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            fd_roles.push(FdRole::MsearchProxy { port });
        }

        // 3. Dynamic TCP listeners
        for (&port, p) in &tcp_proxies {
            poll_fds.push(libc::pollfd {
                fd: p.listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            fd_roles.push(FdRole::TcpListener { port });
        }

        // 4. Active TCP proxy connections
        for (idx, conn) in active_tcp_connections.iter().enumerate() {
            poll_fds.push(libc::pollfd {
                fd: conn.client_fd,
                events: libc::POLLIN,
                revents: 0,
            });
            fd_roles.push(FdRole::TcpClient { conn_index: idx });

            poll_fds.push(libc::pollfd {
                fd: conn.server_fd,
                events: libc::POLLIN,
                revents: 0,
            });
            fd_roles.push(FdRole::TcpServer { conn_index: idx });
        }

        // Call poll with a 1-second timeout (to allow periodic inline GC execution)
        let ret = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                1000,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                log::error!("poll failed: {}", err);
            }
            continue;
        }

        if ret == 0 {
            // Timeout reached, loop will perform GC and rebuild poll_fds
            continue;
        }

        let mut closed_connections = std::collections::HashSet::new();

        // Process active events
        for i in 0..poll_fds.len() {
            let revents = poll_fds[i].revents;
            if revents == 0 {
                continue;
            }

            // If error/hangup on a TCP proxy socket, close it
            if (revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 && (revents & libc::POLLIN) == 0 {
                match fd_roles[i] {
                    FdRole::TcpClient { conn_index } | FdRole::TcpServer { conn_index } => {
                        closed_connections.insert(conn_index);
                    }
                    _ => {}
                }
                continue;
            }

            if (revents & libc::POLLIN) != 0 {
                match fd_roles[i] {
                    FdRole::MainUdp => {
                        // Read incoming UDP packets from the main socket
                        let res = match recv_with_ancillary(main_fd, &mut buf) {
                            Ok(Some(r)) => {
                                log::debug!(
                                    "Received UDP packet: len={}, src={}, dst={}, ifindex={}",
                                    r.len,
                                    r.src_addr,
                                    r.dst_ip,
                                    r.ifindex
                                );
                                r
                            }
                            Ok(None) => continue,
                            Err(e) => {
                                log::error!("Error receiving: {}", e);
                                continue;
                            }
                        };

                        // Loop Prevention check
                        let rx_id = if args.ttl_id {
                            res.ttl.saturating_sub(TTL_ID_OFFSET)
                        } else {
                            res.tos >> 2
                        };

                        if args.ttl_id {
                            if res.ttl == args.id + TTL_ID_OFFSET {
                                log::trace!("TTL loop prevented: rx_ttl = {}, ID = {}", res.ttl, args.id);
                                continue;
                            }
                        } else {
                            if rx_id == args.id {
                                log::trace!(
                                    "DSCP loop prevented: rx_tos DSCP = {}, ID = {}",
                                    rx_id,
                                    args.id
                                );
                                continue;
                            }
                        }

                        // blockid check
                        if args.blockid.contains(&rx_id) {
                            log::trace!(
                                "BlockID loop prevented: rx_id = {}, blocked IDs = {:?}",
                                rx_id,
                                args.blockid
                            );
                            continue;
                        }

                        // Check if from managed interface
                        if !interfaces.contains_key(&res.ifindex) {
                            continue;
                        }

                        // Apply CIDR network filter rules
                        if !check_cidr_acl(
                            &acl_rules,
                            default_acl_action.clone(),
                            *res.src_addr.ip(),
                        ) {
                            log::trace!("Packet from {} blocked by CIDR ACL", res.src_addr.ip());
                            continue;
                        }

                        // Check for SSDP M-SEARCH requests
                        let mut is_msearch = false;
                        let mut msearch_act = MsearchAction::Forward;
                        let payload = &buf[..res.len];

                        if payload.starts_with(b"M-SEARCH * HTTP/1.1\r\n") {
                            is_msearch = true;
                            // Parse ST (Search Target)
                            let text = String::from_utf8_lossy(payload);
                            let mut matched_filter = None;
                            for line in text.split("\r\n") {
                                if line.to_ascii_lowercase().starts_with("st:") {
                                    let st_val = line.splitn(2, ':').nth(1).unwrap_or("").trim();
                                    matched_filter = msearch_filters.iter().find(|f| f.search_string == st_val);
                                    break;
                                }
                            }

                            msearch_act = if let Some(filter) = matched_filter {
                                filter.action.clone()
                            } else {
                                default_msearch_action.clone()
                            };
                            log::debug!("SSDP M-SEARCH query matched action: {:?}", msearch_act);
                        }

                        if is_msearch {
                            match msearch_act {
                                MsearchAction::Block => continue,
                                MsearchAction::Forward => {
                                    // Relay as normal UDP packet
                                    let _ = relay_packet(
                                        &args,
                                        &interfaces,
                                        res.ifindex,
                                        None,
                                        *res.src_addr.ip(),
                                        res.src_addr.port(),
                                        res.dst_ip,
                                        args.port,
                                        res.ttl,
                                        res.tos,
                                        payload,
                                    );
                                }
                                MsearchAction::Proxy | MsearchAction::Dial => {
                                    // SSDP proxy logic
                                    let existing_port = msearch_proxies
                                        .iter()
                                        .find(|(_, p)| {
                                            p.client_addr == res.src_addr && p.src_ifindex == res.ifindex
                                        })
                                        .map(|(&port, _)| port);

                                    let proxy_port = if let Some(port) = existing_port {
                                        if let Some(p) = msearch_proxies.get_mut(&port) {
                                            p.last_active = Instant::now();
                                        }
                                        port
                                    } else {
                                        // Create dynamic UDP proxy socket
                                        match UdpSocket::bind("0.0.0.0:0") {
                                            Ok(sock) => {
                                                sock.set_nonblocking(true).unwrap();
                                                let port = sock.local_addr().unwrap().port();
                                                msearch_proxies.insert(
                                                    port,
                                                    MsearchProxyInfo {
                                                        sock,
                                                        client_addr: res.src_addr,
                                                        src_ifindex: res.ifindex,
                                                        action: msearch_act.clone(),
                                                        last_active: Instant::now(),
                                                    },
                                                );
                                                log::info!(
                                                    "Created dynamic SSDP proxy on port {} for client {}",
                                                    port,
                                                    res.src_addr
                                                );
                                                port
                                            }
                                            Err(e) => {
                                                log::warn!("Failed to create dynamic SSDP proxy: {}", e);
                                                0
                                            }
                                        }
                                    };

                                    if proxy_port != 0 {
                                        // Forward M-SEARCH query through target interfaces with rewritten source port
                                        let _ = relay_packet(
                                            &args,
                                            &interfaces,
                                            res.ifindex,
                                            None,
                                            *res.src_addr.ip(),
                                            proxy_port,
                                            res.dst_ip,
                                            args.port,
                                            res.ttl,
                                            res.tos,
                                            payload,
                                        );
                                    }
                                }
                            }
                        } else {
                            // Relaying normal UDP packet
                            let _ = relay_packet(
                                &args,
                                &interfaces,
                                res.ifindex,
                                None,
                                *res.src_addr.ip(),
                                res.src_addr.port(),
                                res.dst_ip,
                                args.port,
                                res.ttl,
                                res.tos,
                                payload,
                            );
                        }
                    }
                    FdRole::MsearchProxy { port } => {
                        if let Some(p) = msearch_proxies.get_mut(&port) {
                            let mut ubuf = vec![0u8; 8192];
                            match p.sock.recv_from(&mut ubuf) {
                                Ok((n, _)) => {
                                    p.last_active = Instant::now();

                                    let client_facing_ip = {
                                        let iface_info = interfaces.get(&p.src_ifindex).unwrap();
                                        let ip = iface_info
                                            .iface
                                            .ips
                                            .iter()
                                            .find(|ip| ip.is_ipv4())
                                            .unwrap()
                                            .ip();
                                        match ip {
                                            IpAddr::V4(v4) => v4,
                                            _ => continue,
                                        }
                                    };

                                    let mut rewritten = ubuf[..n].to_vec();

                                    if p.action == MsearchAction::Dial {
                                        if let Some((srv_ip, srv_port)) =
                                            extract_ip_port_from_header(&rewritten, "Location")
                                        {
                                            let existing = tcp_proxies.values().find(|proxy| {
                                                proxy.target_addr == SocketAddrV4::new(srv_ip, srv_port)
                                                    && proxy.client_facing_ip == client_facing_ip
                                            });

                                            let tcp_port = if let Some(proxy) = existing {
                                                proxy.listener.local_addr().unwrap().port()
                                            } else {
                                                match TcpListener::bind(SocketAddrV4::new(client_facing_ip, 0)) {
                                                    Ok(listener) => {
                                                        let local_port = listener.local_addr().unwrap().port();
                                                        listener.set_nonblocking(true).unwrap();
                                                        tcp_proxies.insert(
                                                            local_port,
                                                            TcpProxyListenerInfo {
                                                                listener,
                                                                target_addr: SocketAddrV4::new(srv_ip, srv_port),
                                                                client_facing_ip,
                                                                last_active: Instant::now(),
                                                            },
                                                        );
                                                        log::info!(
                                                            "Created Location TCP proxy on port {} for target {}:{}",
                                                            local_port,
                                                            srv_ip,
                                                            srv_port
                                                        );
                                                        local_port
                                                    }
                                                    Err(e) => {
                                                        log::warn!("Failed to create Location TCP proxy: {}", e);
                                                        0
                                                    }
                                                }
                                            };

                                            if tcp_port != 0 {
                                                rewritten = replace_header_value(
                                                    &rewritten,
                                                    "Location",
                                                    &format!("http://{}:{}/dd.xml", client_facing_ip, tcp_port),
                                                );
                                            }
                                        }
                                    }

                                    // Relay SSDP reply back to original client
                                    let data_str = String::from_utf8_lossy(&rewritten);
                                    log::debug!(
                                        "SSDP Relay Response to client {}: \n{}",
                                        p.client_addr,
                                        data_str
                                    );

                                    let _ = relay_packet(
                                        &args,
                                        &interfaces,
                                        0,
                                        Some(p.src_ifindex),
                                        client_facing_ip,
                                        port,
                                        *p.client_addr.ip(),
                                        p.client_addr.port(),
                                        TTL_ID_OFFSET,
                                        0,
                                        &rewritten,
                                    );
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                Err(e) => {
                                    log::warn!("Dynamic UDP proxy recv failed on port {}: {}", port, e);
                                }
                            }
                        }
                    }
                    FdRole::TcpListener { port } => {
                        if let Some(proxy_info) = tcp_proxies.get_mut(&port) {
                            if let Ok((client_stream, _)) = proxy_info.listener.accept() {
                                log::info!(
                                    "TCP proxy accepted connection on port {} targeting {}",
                                    port,
                                    proxy_info.target_addr
                                );
                                proxy_info.last_active = Instant::now();

                                match TcpStream::connect(proxy_info.target_addr) {
                                    Ok(server_stream) => {
                                        client_stream.set_nonblocking(true).unwrap();
                                        server_stream.set_nonblocking(true).unwrap();
                                        let client_fd = client_stream.as_raw_fd();
                                        let server_fd = server_stream.as_raw_fd();

                                        active_tcp_connections.push(TcpProxyConnection {
                                            client: client_stream,
                                            server: server_stream,
                                            client_fd,
                                            server_fd,
                                            target_addr: proxy_info.target_addr,
                                            client_facing_ip: proxy_info.client_facing_ip,
                                            last_active: Instant::now(),
                                        });
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "TCP proxy failed to connect to target {}: {}",
                                            proxy_info.target_addr,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    FdRole::TcpClient { conn_index } => {
                        if conn_index < active_tcp_connections.len() {
                            let conn = &mut active_tcp_connections[conn_index];
                            conn.last_active = Instant::now();
                            let mut tbuf = vec![0u8; 16384];
                            match conn.client.read(&mut tbuf) {
                                Ok(0) => {
                                    closed_connections.insert(conn_index);
                                }
                                Ok(n) => {
                                    // Rewrite Host header if HTTP request
                                    let rewritten = replace_header_value(
                                        &tbuf[..n],
                                        "Host",
                                        &format!("{}:{}", conn.target_addr.ip(), conn.target_addr.port()),
                                    );
                                    if let Err(e) = conn.server.write_all(&rewritten) {
                                        log::warn!("TCP proxy write to server failed: {}", e);
                                        closed_connections.insert(conn_index);
                                    }
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                Err(e) => {
                                    log::warn!("TCP proxy read from client failed: {}", e);
                                    closed_connections.insert(conn_index);
                                }
                            }
                        }
                    }
                    FdRole::TcpServer { conn_index } => {
                        if conn_index < active_tcp_connections.len() {
                            let conn = &mut active_tcp_connections[conn_index];
                            conn.last_active = Instant::now();
                            let mut tbuf = vec![0u8; 16384];
                            match conn.server.read(&mut tbuf) {
                                Ok(0) => {
                                    closed_connections.insert(conn_index);
                                }
                                Ok(n) => {
                                    let mut rewritten = tbuf[..n].to_vec();

                                    // Check for Application-URL header
                                    if let Some((app_ip, app_port)) =
                                        extract_ip_port_from_header(&rewritten, "Application-URL")
                                    {
                                        let client_facing_ip = conn.client_facing_ip;
                                        let existing = tcp_proxies.values().find(|p| {
                                            p.target_addr == SocketAddrV4::new(app_ip, app_port)
                                                && p.client_facing_ip == client_facing_ip
                                        });

                                        let port = if let Some(p) = existing {
                                            p.listener.local_addr().unwrap().port()
                                        } else {
                                            match TcpListener::bind(SocketAddrV4::new(client_facing_ip, 0)) {
                                                Ok(listener) => {
                                                    let local_port = listener.local_addr().unwrap().port();
                                                    listener.set_nonblocking(true).unwrap();
                                                    tcp_proxies.insert(
                                                        local_port,
                                                        TcpProxyListenerInfo {
                                                            listener,
                                                            target_addr: SocketAddrV4::new(app_ip, app_port),
                                                            client_facing_ip,
                                                            last_active: Instant::now(),
                                                        },
                                                    );
                                                    log::info!(
                                                        "Created dynamic REST TCP proxy on port {} for target {}:{}",
                                                        local_port,
                                                        app_ip,
                                                        app_port
                                                    );
                                                    local_port
                                                }
                                                Err(e) => {
                                                    log::warn!("Failed to create REST TCP proxy: {}", e);
                                                    0
                                                }
                                            }
                                        };

                                        if port != 0 {
                                            rewritten = replace_header_value(
                                                &rewritten,
                                                "Application-URL",
                                                &format!("http://{}:{}/apps/", client_facing_ip, port),
                                            );
                                        }
                                    }

                                    // Check for Location header
                                    if let Some((loc_ip, loc_port)) = extract_ip_port_from_header(&rewritten, "Location") {
                                        let client_facing_ip = conn.client_facing_ip;
                                        let existing = tcp_proxies.values().find(|p| {
                                            p.target_addr == SocketAddrV4::new(loc_ip, loc_port)
                                                && p.client_facing_ip == client_facing_ip
                                        });

                                        let port = if let Some(p) = existing {
                                            p.listener.local_addr().unwrap().port()
                                        } else {
                                            match TcpListener::bind(SocketAddrV4::new(client_facing_ip, 0)) {
                                                Ok(listener) => {
                                                    let local_port = listener.local_addr().unwrap().port();
                                                    listener.set_nonblocking(true).unwrap();
                                                    tcp_proxies.insert(
                                                        local_port,
                                                        TcpProxyListenerInfo {
                                                            listener,
                                                            target_addr: SocketAddrV4::new(loc_ip, loc_port),
                                                            client_facing_ip,
                                                            last_active: Instant::now(),
                                                        },
                                                    );
                                                    log::info!(
                                                        "Created dynamic REST TCP proxy on port {} for target {}:{}",
                                                        local_port,
                                                        loc_ip,
                                                        loc_port
                                                    );
                                                    local_port
                                                }
                                                Err(e) => {
                                                    log::warn!("Failed to create REST TCP proxy: {}", e);
                                                    0
                                                }
                                            }
                                        };

                                        if port != 0 {
                                            rewritten = replace_header_value(
                                                &rewritten,
                                                "Location",
                                                &format!("http://{}:{}/", client_facing_ip, port),
                                            );
                                        }
                                    }

                                    if let Err(e) = conn.client.write_all(&rewritten) {
                                        log::warn!("TCP proxy write to client failed: {}", e);
                                        closed_connections.insert(conn_index);
                                    }
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                                Err(e) => {
                                    log::warn!("TCP proxy read from server failed: {}", e);
                                    closed_connections.insert(conn_index);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Close and remove closed active TCP connections
        if !closed_connections.is_empty() {
            let mut sorted_indices: Vec<usize> = closed_connections.into_iter().collect();
            sorted_indices.sort_by(|a, b| b.cmp(a));
            for idx in sorted_indices {
                if idx < active_tcp_connections.len() {
                    log::info!("Closing and removing active TCP proxy connection");
                    active_tcp_connections.remove(idx);
                }
            }
        }
    }

    log::info!("Shutting down cleanly.");
    Ok(())
}
