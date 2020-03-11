
use crate::protocol::Protocol;
use crate::protocol::ProtocolSet;
use crate::name_server::NameServer;
use crate::name_server::ROOT_V4_SERVERS;
use crate::name_server::ROOT_V6_SERVERS;


#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct ResolvOptions {
    pub use_ipv4: bool,
    pub use_ipv6: bool,
    pub use_system_hosts: bool,
    pub use_system_name_server: bool,
    pub use_mdns: bool,
    
    pub attempts: usize,
    pub max_ns_hop: usize,
    pub timeout: std::time::Duration,
    pub connect_timeout: std::time::Duration,
    pub read_timeout: std::time::Duration,
    pub write_timeout: std::time::Duration,
}

impl Default for ResolvOptions {
    fn default() -> Self {
        Self {
            use_ipv4: true,
            use_ipv6: false,
            use_system_hosts: false,
            use_system_name_server: false,
            use_mdns: false,
            attempts: 4,
            max_ns_hop: 16,
            timeout: std::time::Duration::from_secs(5),
            connect_timeout: std::time::Duration::from_secs(5),
            read_timeout: std::time::Duration::from_secs(5),
            write_timeout: std::time::Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub resolv_options: ResolvOptions,
    pub upstream_name_servers: Vec<NameServer>,
    pub bind: NameServer,
}

impl Default for Config {
    fn default() -> Self {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        Self {
            resolv_options: ResolvOptions::default(),
            upstream_name_servers: Vec::new(),
            bind: NameServer::new_default(Some("localhost".to_string()), ip),
        }
    }
}


// example.com
//      93.184.216.34
//      2606:2800:220:1:248:1893:25c8:1946
pub async fn is_ipv4_support() -> bool {
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect("93.184.216.34:80")
    )
    .await;
    match stream {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            // macOS ERROR_CODE:  65,  MSG: No route to host
            // Linux ERROR_CODE: 101,  MSG: Network is unreachable
            false
        },
        // Timeout
        Err(_) => true,
    }
}

pub async fn is_ipv6_support() -> bool {
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect("2606:2800:220:1:248:1893:25c8:1946:80")
    )
    .await;
    match stream {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            // macOS ERROR_CODE:  65,  MSG: No route to host
            // Linux ERROR_CODE: 101,  MSG: Network is unreachable
            false
        },
        // Timeout
        Err(_) => true,
    }
}

pub async fn sort_root_name_servers() -> Vec<NameServer> {
    info!("test root name server speed [START]");

    let mut servers = Vec::new();
    let mut servers2 = Vec::new();

    for (name, ip_addr) in ROOT_V4_SERVERS.iter().chain(ROOT_V6_SERVERS.iter()) {
        let now = std::time::Instant::now();
        let socket_addr = std::net::SocketAddr::new(*ip_addr, 53);
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(socket_addr)
        )
        .await;
        
        let domain_name = Some(name.to_string());
        let name_server = NameServer::new_default(domain_name, *ip_addr);

        if let Ok(Ok(stream)) = stream {
            let duration = now.elapsed();    
            servers.push((duration, name_server));
        } else {
            servers2.push(name_server);
        }
    }

    servers.sort_by_key(|item| item.0);
    servers.reverse();

    for (_, name_server) in servers.into_iter() {
        servers2.push(name_server);
    }

    info!("test root name server speed [DONE]");

    servers2
}
