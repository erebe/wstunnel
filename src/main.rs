use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use clap::Parser;
use hyper::body::Body;
use hyper::Request;
use hyper_openssl::HttpsConnector;
use url::{Host, Url, UrlQuery};

/// Simple program to greet a person
#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Wstunnel {

    #[command(subcommand)]
    commands: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Client(Client),
    Server(Server)
}
#[derive(clap::Args, Debug)]
struct Client {
    /// Name of the person to greet
    #[arg(short='L', long, value_name = "[BIND:]PORT:HOST:PORT", value_parser = parse_env_var)]
    local_to_remote: Vec<LocalToRemote>,
}

#[derive(clap::Args, Debug)]
struct Server {
    /// Name of the person to greet
    #[arg(short='L', long, value_name = "[BIND:]PORT:HOST:PORT", value_parser = parse_env_var)]
    local_to_remote: String,
}

#[derive(Copy, Clone, Debug)]
enum L4Protocol {
    TCP, UDP { timeout: Duration }
}

impl L4Protocol {
    fn new_udp() -> L4Protocol {
        L4Protocol::UDP { timeout: Duration::from_secs(30) }
    }
}

#[derive(Clone, Debug)]
struct LocalToRemote {
    protocol: L4Protocol,
    local: SocketAddr,
    remote: (Host<String>, u16),
}

fn parse_env_var(arg: &str) -> Result<LocalToRemote, std::io::Error> {
    use std::io::Error;

    let (mut protocol, arg) = match &arg[..6] {
        "tcp://" => (L4Protocol::TCP, &arg[6..]),
        "udp://" => (L4Protocol::new_udp(), &arg[6..]),
        _ => (L4Protocol::TCP, arg)
    };

    let (bind, remaining) = if arg.starts_with('[') {
        // ipv6 bind
        let Some((ipv6_str, remaining)) = arg.split_once(']') else {
            return Err(Error::new(ErrorKind::InvalidInput, format!("cannot parse IPv6 bind from {}", arg)));
        };
        let Ok(ipv6_addr) = Ipv6Addr::from_str(&ipv6_str[1..]) else {
            return Err(Error::new(ErrorKind::InvalidInput, format!("cannot parse IPv6 bind from {}", ipv6_str)));
        };

        (IpAddr::V6(ipv6_addr), remaining)
    } else {
        // Maybe ipv4 addr
        let Some((ipv4_str, remaining)) = arg.split_once(':') else {
            return Err(Error::new(ErrorKind::InvalidInput, format!("cannot parse IPv4 bind from {}", arg)));
        };

        match Ipv4Addr::from_str(ipv4_str)  {
            Ok(ip4_addr) => (IpAddr::V4(ip4_addr), remaining),
            // Must be the port, so we default to ipv6 bind
            Err(_) => (IpAddr::V6(Ipv6Addr::from_str("::1").unwrap()), arg)
        }
    };

    let Some((port_str, remaining)) = remaining.trim_start_matches(':').split_once(':') else {
        return Err(Error::new(ErrorKind::InvalidInput, format!("cannot parse bind port from {}", remaining)));
    };

    let Ok(bind_port): Result<u16, _> = port_str.parse() else {
        return Err(Error::new(ErrorKind::InvalidInput, format!("cannot parse bind port from {}", port_str)));
    };


    let Ok(remote) = Url::parse(&format!("fake://{}", remaining)) else {
        return Err(Error::new(ErrorKind::InvalidInput, format!("cannot parse remote from {}", remaining)));
    };

    let Some(remote_host) = remote.host() else {
        return Err(Error::new(ErrorKind::InvalidInput, format!("cannot parse remote host from {}", remaining)));
    };

    let Some(remote_port) = remote.port() else {
        return Err(Error::new(ErrorKind::InvalidInput, format!("cannot parse remote port from {}", remaining)));
    };

    match &mut protocol {
        L4Protocol::TCP => {}
        L4Protocol::UDP { ref mut timeout, .. } => {
            let options: BTreeMap<Cow<'_, str>, Cow<'_, str>> = remote.query_pairs().collect();
            if let Some(duration) = options.get("timeout_sec")
                .and_then(|x| x.parse::<u64>().ok())
                .map(|x| Duration::from_secs(x)) {
                *timeout = duration;
            }
        }
    };

    Ok(LocalToRemote {
        protocol,
        local: SocketAddr::new(bind, bind_port),
        remote: (remote_host.to_owned(), remote_port)
    })
}

fn main() {
    println!("Hello, world!");
    let args = Wstunnel::parse();

    println!("Hello {:?}!", args)

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build().unwrap();


    let mut conn = HttpsConnector::new()?;
    conn.set_callback(move |c, _| {
        // Prevent native TLS lib from inferring and verifying a default SNI.
        c.set_use_server_name_indication(false);
        c.set_verify_hostname(false);

        // And set a custom SNI instead.
        c.set_hostname("somewhere.com")
    });
    Client::builder()
        .build::<_, Body>(conn)
        .request(Request::get("somewhere-else.com").body(())?)
        .await?;

    reqwest::Proxy::all("https://google.com").unwrap().basic_auth("", "")

}
