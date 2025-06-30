use crate::tunnel::LocalProtocol;
pub use hyper::http::{HeaderName, HeaderValue};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio_rustls::rustls::pki_types::DnsName;
use url::{Host, Url};

pub const DEFAULT_CLIENT_UPGRADE_PATH_PREFIX: &str = "v1";

#[derive(Clone, Debug)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct Client {
    /// Listen on local and forwards traffic from remote. Can be specified multiple times
    /// examples:
    /// 'tcp://1212:google.com:443'      =>       listen locally on tcp on port 1212 and forward to google.com on port 443
    /// 'tcp://2:n.lan:4?proxy_protocol' =>       listen locally on tcp on port 2 and forward to n.lan on port 4
    ///                                           Send a proxy protocol header v2 when establishing connection to n.lan
    ///
    /// 'udp://1212:1.1.1.1:53'          =>       listen locally on udp on port 1212 and forward to cloudflare dns 1.1.1.1 on port 53
    /// 'udp://1212:1.1.1.1:53?timeout_sec=10'    timeout_sec on udp force close the tunnel after 10sec. Set it to 0 to disable the timeout [default: 30]
    ///
    /// 'socks5://[::1]:1212'            =>       listen locally with socks5 on port 1212 and forward dynamically requested tunnel
    /// 'socks5://[::1]:1212?login=admin&password=admin' => listen locally with socks5 on port 1212 and only accept connection with login=admin and password=admin
    ///
    /// 'http://[::1]:1212'              =>       start a http proxy on port 1212 and forward dynamically requested tunnel
    /// 'http://[::1]:1212?login=admin&password=admin' => start a http proxy on port 1212 and only accept connection with login=admin and password=admin
    ///
    /// 'tproxy+tcp://[::1]:1212'        =>       listen locally on tcp on port 1212 as a *transparent proxy* and forward dynamically requested tunnel
    /// 'tproxy+udp://[::1]:1212?timeout_sec=10'  listen locally on udp on port 1212 as a *transparent proxy* and forward dynamically requested tunnel
    ///                                           linux only and requires sudo/CAP_NET_ADMIN
    ///
    /// 'stdio://google.com:443'         =>       listen for data from stdio, mainly for `ssh -o ProxyCommand="wstunnel client -L stdio://%h:%p ws://localhost:8080" my-server`
    ///
    /// 'unix:///tmp/wstunnel.sock:g.com:443' =>  listen for data from unix socket of path /tmp/wstunnel.sock and forward to g.com:443
    #[cfg_attr(feature = "clap", arg(short='L', long, value_name = "{tcp,udp,socks5,stdio,unix}://[BIND:]PORT:HOST:PORT", value_parser = parsers::parse_tunnel_arg, verbatim_doc_comment))]
    pub local_to_remote: Vec<LocalToRemote>,

    /// Listen on remote and forwards traffic from local. Can be specified multiple times. Only tcp is supported
    /// examples:
    /// 'tcp://1212:google.com:443'      =>     listen on server for incoming tcp cnx on port 1212 and forward to google.com on port 443 from local machine
    /// 'udp://1212:1.1.1.1:53'          =>     listen on server for incoming udp on port 1212 and forward to cloudflare dns 1.1.1.1 on port 53 from local machine
    /// 'socks5://[::1]:1212'            =>     listen on server for incoming socks5 request on port 1212 and forward dynamically request from local machine (login/password is supported)
    /// 'http://[::1]:1212'         =>     listen on server for incoming http proxy request on port 1212 and forward dynamically request from local machine (login/password is supported)
    /// 'unix://wstunnel.sock:g.com:443' =>     listen on server for incoming data from unix socket of path wstunnel.sock and forward to g.com:443 from local machine
    #[cfg_attr(feature = "clap", arg(short='R', long, value_name = "{tcp,udp,socks5,unix}://[BIND:]PORT:HOST:PORT", value_parser = parsers::parse_reverse_tunnel_arg, verbatim_doc_comment))]
    pub remote_to_local: Vec<LocalToRemote>,

    /// (linux only) Mark network packet with SO_MARK sockoption with the specified value.
    /// You need to use {root, sudo, capabilities} to run wstunnel when using this option
    #[cfg_attr(feature = "clap", arg(long, value_name = "INT", verbatim_doc_comment))]
    pub socket_so_mark: Option<u32>,

    /// Client will maintain a pool of open connection to the server, in order to speed up the connection process.
    /// This option set the maximum number of connection that will be kept open.
    /// This is useful if you plan to create/destroy a lot of tunnel (i.e: with socks5 to navigate with a browser)
    /// It will avoid the latency of doing tcp + tls handshake with the server
    #[cfg_attr(
        feature = "clap",
        arg(short = 'c', long, value_name = "INT", default_value = "0", verbatim_doc_comment)
    )]
    pub connection_min_idle: u32,

    /// The maximum of time in seconds while we are going to try to connect to the server before failing the connection/tunnel request
    #[cfg_attr(feature = "clap", arg(
        long,
        value_name = "DURATION(s|m|h)",
        default_value = "5m",
        value_parser = parsers::parse_duration_sec,
        alias = "connection-retry-max-backoff-sec",
        verbatim_doc_comment
    ))]
    pub connection_retry_max_backoff: Duration,

    /// When using reverse tunnel, the client will try to always keep a connection to the server to await for new tunnels
    /// This delay is the maximum of time the client will wait before trying to reconnect to the server in case of failure.
    /// The client follows an exponential backoff strategy until it reaches this maximum delay
    /// By default, the client tries to reconnect every 1 second
    #[cfg_attr(feature = "clap", arg(
        long,
        value_name = "DURATION(s|m|h)",
        default_value = "1s",
        value_parser = parsers::parse_duration_sec,
        alias = "reverse-tunnel-connection-retry-max-backoff-sec",
        verbatim_doc_comment
    ))]
    pub reverse_tunnel_connection_retry_max_backoff: Duration,

    /// Domain name that will be used as SNI during TLS handshake
    /// Warning: If you are behind a CDN (i.e: Cloudflare) you must set this domain also in the http HOST header.
    ///          or it will be flagged as fishy and your request rejected
    #[cfg_attr(feature = "clap", arg(long, value_name = "DOMAIN_NAME", value_parser = parsers::parse_sni_override, verbatim_doc_comment))]
    pub tls_sni_override: Option<DnsName<'static>>,

    /// Disable sending SNI during TLS handshake
    /// Warning: Most reverse proxies rely on it
    #[cfg_attr(
        feature = "clap",
        arg(
            long,
            verbatim_doc_comment,
            conflicts_with = "tls_sni_override",
            conflicts_with = "tls_ech_enable"
        )
    )]
    pub tls_sni_disable: bool,

    /// Enable ECH (encrypted sni) during TLS handshake to wstunnel server.
    /// Warning: Ech DNS config is not refreshed over time. It is retrieved only once at startup of the program  
    #[cfg_attr(feature = "clap", arg(long, verbatim_doc_comment))]
    pub tls_ech_enable: bool,

    /// Enable TLS certificate verification.
    /// Disabled by default. The client will happily connect to any server with self-signed certificate.
    #[cfg_attr(feature = "clap", arg(long, verbatim_doc_comment))]
    pub tls_verify_certificate: bool,

    /// If set, will use this http proxy to connect to the server
    #[cfg_attr(
        feature = "clap",
        arg(
            short = 'p',
            long,
            value_name = "USER:PASS@HOST:PORT",
            verbatim_doc_comment,
            env = "HTTP_PROXY"
        )
    )]
    pub http_proxy: Option<String>,

    /// If set, will use this login to connect to the http proxy. Override the one from --http-proxy
    #[cfg_attr(
        feature = "clap",
        arg(long, value_name = "LOGIN", verbatim_doc_comment, env = "WSTUNNEL_HTTP_PROXY_LOGIN")
    )]
    pub http_proxy_login: Option<String>,

    /// If set, will use this password to connect to the http proxy. Override the one from --http-proxy
    #[cfg_attr(
        feature = "clap",
        arg(
            long,
            value_name = "PASSWORD",
            verbatim_doc_comment,
            env = "WSTUNNEL_HTTP_PROXY_PASSWORD"
        )
    )]
    pub http_proxy_password: Option<String>,

    /// Use a specific prefix that will show up in the http path during the upgrade request.
    /// Useful if you need to route requests server side but don't have vhosts
    /// When using mTLS this option overrides the default behavior of using the common name of the
    /// client's certificate. This will likely result in the wstunnel server rejecting the connection.
    #[cfg_attr(feature = "clap", arg(
        short = 'P',
        long,
        default_value = DEFAULT_CLIENT_UPGRADE_PATH_PREFIX,
        verbatim_doc_comment,
        env = "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX"
    ))]
    pub http_upgrade_path_prefix: String,

    /// Pass authorization header with basic auth credentials during the upgrade request.
    /// If you need more customization, you can use the http_headers option.
    #[cfg_attr(feature = "clap", arg(long, value_name = "USER[:PASS]", value_parser = parsers::parse_http_credentials, verbatim_doc_comment))]
    pub http_upgrade_credentials: Option<HeaderValue>,

    /// Frequency at which the client will send websocket pings to the server.
    /// Set to zero to disable.
    #[cfg_attr(feature = "clap", arg(
        long,
        value_name = "DURATION(s|m|h)",
        default_value = "30s",
        value_parser = parsers::parse_duration_sec,
        alias = "websocket-ping-frequency-sec",
        verbatim_doc_comment
    ))]
    pub websocket_ping_frequency: Option<Duration>,

    /// Enable the masking of websocket frames. Default is false
    /// Enable this option only if you use unsecure (non TLS) websocket server, and you see some issues. Otherwise, it is just overhead.
    #[cfg_attr(feature = "clap", arg(long, default_value = "false", verbatim_doc_comment))]
    pub websocket_mask_frame: bool,

    /// Send custom headers in the upgrade request
    /// Can be specified multiple time
    #[cfg_attr(feature = "clap", arg(short='H', long, value_name = "HEADER_NAME: HEADER_VALUE", value_parser = parsers::parse_http_headers, verbatim_doc_comment))]
    pub http_headers: Vec<(HeaderName, HeaderValue)>,

    /// Send custom headers in the upgrade request reading them from a file.
    /// It overrides http_headers specified from command line.
    /// File is read everytime and file format must contain lines with `HEADER_NAME: HEADER_VALUE`
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE_PATH", verbatim_doc_comment))]
    pub http_headers_file: Option<PathBuf>,

    /// Address of the wstunnel server
    /// You can either use websocket or http2 as transport protocol. Use websocket if you are unsure.
    /// Example: For websocket with TLS wss://wstunnel.example.com or without ws://wstunnel.example.com
    ///          For http2 with TLS https://wstunnel.example.com or without http://wstunnel.example.com
    ///
    /// *WARNING* HTTP2 as transport protocol is harder to make it works because:
    ///   - If you are behind a (reverse) proxy/CDN they are going to buffer the whole request before forwarding it to the server
    ///     Obviously, this is not going to work for tunneling traffic
    ///   - if you have wstunnel behind a reverse proxy, most of them (i.e: nginx) are going to turn http2 request into http1
    ///     This is not going to work, because http1 does not support streaming naturally
    ///   - The only way to make it works with http2 is to have wstunnel directly exposed to the internet without any reverse proxy in front of it
    #[cfg_attr(feature = "clap", arg(value_name = "ws[s]|http[s]://wstunnel.server.com[:port]", value_parser = parsers::parse_server_url, verbatim_doc_comment))]
    pub remote_addr: Url,

    /// [Optional] Certificate (pem) to present to the server when connecting over TLS (HTTPS).
    /// Used when the server requires clients to authenticate themselves with a certificate (i.e. mTLS).
    /// Unless overridden, the HTTP upgrade path will be configured to be the common name (CN) of the certificate.
    /// The certificate will be automatically reloaded if it changes
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE_PATH", verbatim_doc_comment))]
    pub tls_certificate: Option<PathBuf>,

    /// [Optional] The private key for the corresponding certificate used with mTLS.
    /// The certificate will be automatically reloaded if it changes
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE_PATH", verbatim_doc_comment))]
    pub tls_private_key: Option<PathBuf>,

    /// Dns resolver to use to lookup ips of domain name. Can be specified multiple time
    /// Example:
    ///  dns://1.1.1.1 for using udp
    ///  dns+https://1.1.1.1?sni=cloudflare-dns.com for using dns over HTTPS
    ///  dns+tls://8.8.8.8?sni=dns.google for using dns over TLS
    /// For Dns over HTTPS/TLS if an HTTP proxy is configured, it will be used also
    /// To use libc resolver, use
    /// system://0.0.0.0
    ///
    /// **WARN** On windows you may want to specify explicitly the DNS resolver to avoid excessive DNS queries
    #[cfg_attr(feature = "clap", arg(long, verbatim_doc_comment))]
    pub dns_resolver: Vec<Url>,

    /// Enable if you prefer the dns resolver to prioritize IPv4 over IPv6
    /// This is useful if you have a broken IPv6 connection, and want to avoid the delay of trying to connect to IPv6
    /// If you don't have any IPv6 this does not change anything.
    #[cfg_attr(
        feature = "clap",
        arg(
            long,
            default_value = "false",
            env = "WSTUNNEL_DNS_PREFER_IPV4",
            verbatim_doc_comment
        )
    )]
    pub dns_resolver_prefer_ipv4: bool,
}

#[derive(Debug)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct Server {
    /// Address of the wstunnel server to bind to
    /// Example: With TLS wss://0.0.0.0:8080 or without ws://[::]:8080
    ///
    /// The server is capable of detecting by itself if the request is websocket or http2. So you don't need to specify it.
    #[cfg_attr(feature = "clap", arg(value_name = "ws[s]://0.0.0.0[:port]", value_parser = parsers::parse_server_url, verbatim_doc_comment))]
    pub remote_addr: Url,

    /// (linux only) Mark network packet with SO_MARK sockoption with the specified value.
    /// You need to use {root, sudo, capabilities} to run wstunnel when using this option
    #[cfg_attr(feature = "clap", arg(long, value_name = "INT", verbatim_doc_comment))]
    pub socket_so_mark: Option<u32>,

    /// Frequency at which the server will send websocket ping to client.
    /// Set to zero to disable.
    #[cfg_attr(feature = "clap", arg(
        long,
        value_name = "DURATION(s|m|h)",
        default_value = "30s",
        value_parser = parsers::parse_duration_sec,
        alias = "websocket-ping-frequency-sec",
        verbatim_doc_comment
    ))]
    pub websocket_ping_frequency: Option<Duration>,

    /// Enable the masking of websocket frames. Default is false
    /// Enable this option only if you use unsecure (non TLS) websocket server, and you see some issues. Otherwise, it is just overhead.
    #[cfg_attr(feature = "clap", arg(long, default_value = "false", verbatim_doc_comment))]
    pub websocket_mask_frame: bool,

    /// Dns resolver to use to lookup ips of domain name
    /// This option is not going to work if you use transparent proxy
    /// Can be specified multiple time
    /// Example:
    ///  dns://1.1.1.1 for using udp
    ///  dns+https://1.1.1.1?sni=cloudflare-dns.com for using dns over HTTPS
    ///  dns+tls://8.8.8.8?sni=dns.google for using dns over TLS
    /// To use libc resolver, use
    /// system://0.0.0.0
    #[cfg_attr(feature = "clap", arg(long, verbatim_doc_comment))]
    pub dns_resolver: Vec<Url>,

    /// Enable if you prefer the dns resolver to prioritize IPv4 over IPv6
    /// This is useful if you have a broken IPv6 connection, and want to avoid the delay of trying to connect to IPv6
    /// If you don't have any IPv6 this does not change anything.
    #[cfg_attr(
        feature = "clap",
        arg(
            long,
            default_value = "false",
            env = "WSTUNNEL_DNS_PREFER_IPV4",
            verbatim_doc_comment
        )
    )]
    pub dns_resolver_prefer_ipv4: bool,

    /// Server will only accept connection from the specified tunnel information.
    /// Can be specified multiple time
    /// Example: --restrict-to "google.com:443" --restrict-to "localhost:22"
    #[cfg_attr(
        feature = "clap",
        arg(
            long,
            value_name = "DEST:PORT",
            verbatim_doc_comment,
            conflicts_with = "restrict_config"
        )
    )]
    pub restrict_to: Option<Vec<String>>,

    /// Server will only accept connection from if this specific path prefix is used during websocket upgrade.
    /// Useful if you specify in the client a custom path prefix, and you want the server to only allow this one.
    /// The path prefix act as a secret to authenticate clients
    /// Disabled by default. Accept all path prefix. Can be specified multiple time
    #[cfg_attr(
        feature = "clap",
        arg(
            short = 'r',
            long,
            verbatim_doc_comment,
            conflicts_with = "restrict_config",
            env = "WSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX"
        )
    )]
    pub restrict_http_upgrade_path_prefix: Option<Vec<String>>,

    /// Path to the location of the restriction yaml config file.
    /// Restriction file is automatically reloaded if it changes
    #[cfg_attr(feature = "clap", arg(long, verbatim_doc_comment))]
    pub restrict_config: Option<PathBuf>,

    /// [Optional] Use custom certificate (pem) instead of the default embedded self-signed certificate.
    /// The certificate will be automatically reloaded if it changes
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE_PATH", verbatim_doc_comment))]
    pub tls_certificate: Option<PathBuf>,

    /// [Optional] Use a custom tls key (pem, ec, rsa) that the server will use instead of the default embedded one
    /// The private key will be automatically reloaded if it changes
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE_PATH", verbatim_doc_comment))]
    pub tls_private_key: Option<PathBuf>,

    /// [Optional] Enables mTLS (client authentication with certificate). Argument must be PEM file
    /// containing one or more certificates of CA's of which the certificate of clients needs to be signed with.
    /// The ca will be automatically reloaded if it changes
    #[cfg_attr(feature = "clap", arg(long, value_name = "FILE_PATH", verbatim_doc_comment))]
    pub tls_client_ca_certs: Option<PathBuf>,

    /// If set, will use this http proxy to connect to the client
    #[cfg_attr(
        feature = "clap",
        arg(
            short = 'p',
            long,
            value_name = "USER:PASS@HOST:PORT",
            verbatim_doc_comment,
            env = "HTTP_PROXY"
        )
    )]
    pub http_proxy: Option<String>,

    /// If set, will use this login to connect to the http proxy. Override the one from --http-proxy
    #[cfg_attr(
        feature = "clap",
        arg(long, value_name = "LOGIN", verbatim_doc_comment, env = "WSTUNNEL_HTTP_PROXY_LOGIN")
    )]
    pub http_proxy_login: Option<String>,

    /// If set, will use this password to connect to the http proxy. Override the one from --http-proxy
    #[cfg_attr(
        feature = "clap",
        arg(
            long,
            value_name = "PASSWORD",
            verbatim_doc_comment,
            env = "WSTUNNEL_HTTP_PROXY_PASSWORD"
        )
    )]
    pub http_proxy_password: Option<String>,

    /// Configure how much time a remote-to-local server is going to wait idle (without any new ws clients) before unbinding itself/stopping the server
    /// Default is 190 seconds/3min
    #[cfg_attr(feature = "clap", arg(
        long,
        value_name = "DURATION(s|m|h)",
        default_value = "3m",
        value_parser = parsers::parse_duration_sec,
        alias = "remote-to-local-server-idle-timeout-sec",
        verbatim_doc_comment,
    ))]
    pub remote_to_local_server_idle_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LocalToRemote {
    pub local_protocol: LocalProtocol,
    pub local: SocketAddr,
    pub remote: (Host, u16),
}

#[cfg(feature = "clap")]
mod parsers {
    use super::LocalToRemote;
    use crate::tunnel::LocalProtocol;
    use crate::tunnel::transport::TransportScheme;
    use base64::Engine;
    use hyper::http::{HeaderName, HeaderValue};
    use std::cmp::max;
    use std::collections::BTreeMap;
    use std::io;
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio_rustls::rustls::pki_types::DnsName;
    use url::{Host, Url};

    pub fn parse_duration_sec(arg: &str) -> Result<Duration, io::Error> {
        use std::io::Error;

        let (arg, multiplier) = match &arg[max(0, arg.len() - 1)..] {
            "s" => (&arg[..arg.len() - 1], 1),
            "m" => (&arg[..arg.len() - 1], 60),
            "h" => (&arg[..arg.len() - 1], 3600),
            _ => (arg, 1),
        };

        let Ok(secs) = arg.parse::<u64>() else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse duration of seconds from {arg}"),
            ));
        };

        Ok(Duration::from_secs(secs * multiplier))
    }

    pub fn parse_local_bind(arg: &str) -> Result<(SocketAddr, &str), io::Error> {
        use std::io::Error;

        let (bind, remaining) = if arg.starts_with('[') {
            // ipv6 bind
            let Some((ipv6_str, remaining)) = arg.split_once(']') else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("cannot parse IPv6 bind from {arg}"),
                ));
            };
            let Ok(ipv6_addr) = Ipv6Addr::from_str(&ipv6_str[1..]) else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("cannot parse IPv6 bind from {ipv6_str}"),
                ));
            };

            (IpAddr::V6(ipv6_addr), remaining)
        } else {
            // Maybe ipv4 addr
            let (ipv4_str, remaining) = arg.split_once(':').unwrap_or((arg, ""));
            Ipv4Addr::from_str(ipv4_str).map_or_else(
                |_| (IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap()), arg),
                |ip4_addr| (IpAddr::V4(ip4_addr), remaining),
            )
        };

        let remaining = remaining.trim_start_matches(':');
        let (port_str, remaining) = remaining.split_once([':', '?']).unwrap_or((remaining, ""));

        let Ok(bind_port): Result<u16, _> = port_str.parse() else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse bind port from {port_str}"),
            ));
        };

        Ok((SocketAddr::new(bind, bind_port), remaining))
    }

    #[allow(clippy::type_complexity)]
    pub fn parse_tunnel_dest(remaining: &str) -> Result<(Host<String>, u16, BTreeMap<String, String>), io::Error> {
        use std::io::Error;

        // Using http or else the URL lib don't try to fully parse the host into an IPv4/IPv6
        let Ok(remote) = Url::parse(&format!("https://{remaining}")) else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse remote from {remaining}"),
            ));
        };

        let Some(remote_host) = remote.host() else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse remote host from {remaining}"),
            ));
        };

        let remote_port = match remote.port() {
            Some(remote_port) => remote_port,
            // the url lib does not parse the port if it is the default one
            None if remaining.ends_with(":443") || remaining.contains(":443?") => 443,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("cannot parse remote port from {remaining}"),
                ));
            }
        };

        let options: BTreeMap<String, String> = remote.query_pairs().into_owned().collect();
        Ok((remote_host.to_owned(), remote_port, options))
    }

    pub fn parse_tunnel_arg(arg: &str) -> Result<LocalToRemote, io::Error> {
        use std::io::Error;
        let get_timeout = |options: &BTreeMap<String, String>| {
            options
                .get("timeout_sec")
                .and_then(|x| x.parse::<u64>().ok())
                .map(|d| if d == 0 { None } else { Some(Duration::from_secs(d)) })
                .unwrap_or(Some(Duration::from_secs(30)))
        };
        let get_credentials = |options: &BTreeMap<String, String>| {
            options
                .get("login")
                .and_then(|login| options.get("password").map(|p| (login.to_string(), p.to_string())))
        };
        let get_proxy_protocol = |options: &BTreeMap<String, String>| options.contains_key("proxy_protocol");

        let Some((proto, tunnel_info)) = arg.split_once("://") else {
            return Err(Error::new(ErrorKind::InvalidInput, format!("cannot parse protocol from {arg}")));
        };

        match proto {
            "tcp" => {
                let (local_bind, remaining) = parse_local_bind(tunnel_info)?;
                let (dest_host, dest_port, options) = parse_tunnel_dest(remaining)?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::Tcp {
                        proxy_protocol: get_proxy_protocol(&options),
                    },
                    local: local_bind,
                    remote: (dest_host, dest_port),
                })
            }
            "udp" => {
                let (local_bind, remaining) = parse_local_bind(tunnel_info)?;
                let (dest_host, dest_port, options) = parse_tunnel_dest(remaining)?;

                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::Udp {
                        timeout: get_timeout(&options),
                    },
                    local: local_bind,
                    remote: (dest_host, dest_port),
                })
            }
            "unix" => {
                let Some((path, remote)) = tunnel_info.split_once(':') else {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("cannot parse unix socket path from {arg}"),
                    ));
                };
                let (dest_host, dest_port, options) = parse_tunnel_dest(remote)?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::Unix {
                        path: PathBuf::from(path),
                        proxy_protocol: get_proxy_protocol(&options),
                    },
                    local: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
                    remote: (dest_host, dest_port),
                })
            }
            "http" => {
                let (local_bind, remaining) = parse_local_bind(tunnel_info)?;
                let x = format!("0.0.0.0:0?{remaining}");
                let (dest_host, dest_port, options) = parse_tunnel_dest(&x)?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::HttpProxy {
                        timeout: get_timeout(&options),
                        credentials: get_credentials(&options),
                        proxy_protocol: get_proxy_protocol(&options),
                    },
                    local: local_bind,
                    remote: (dest_host, dest_port),
                })
            }
            "socks5" => {
                let (local_bind, remaining) = parse_local_bind(tunnel_info)?;
                let x = format!("0.0.0.0:0?{remaining}");
                let (dest_host, dest_port, options) = parse_tunnel_dest(&x)?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::Socks5 {
                        timeout: get_timeout(&options),
                        credentials: get_credentials(&options),
                    },
                    local: local_bind,
                    remote: (dest_host, dest_port),
                })
            }
            "stdio" => {
                let (dest_host, dest_port, options) = parse_tunnel_dest(tunnel_info)?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::Stdio {
                        proxy_protocol: get_proxy_protocol(&options),
                    },
                    local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), 0)),
                    remote: (dest_host, dest_port),
                })
            }
            "tproxy+tcp" => {
                let (local_bind, remaining) = parse_local_bind(tunnel_info)?;
                let x = format!("0.0.0.0:0?{remaining}");
                let (dest_host, dest_port, _options) = parse_tunnel_dest(&x)?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::TProxyTcp,
                    local: local_bind,
                    remote: (dest_host, dest_port),
                })
            }
            "tproxy+udp" => {
                let (local_bind, remaining) = parse_local_bind(tunnel_info)?;
                let x = format!("0.0.0.0:0?{remaining}");
                let (dest_host, dest_port, options) = parse_tunnel_dest(&x)?;
                Ok(LocalToRemote {
                    local_protocol: LocalProtocol::TProxyUdp {
                        timeout: get_timeout(&options),
                    },
                    local: local_bind,
                    remote: (dest_host, dest_port),
                })
            }
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid local protocol for tunnel {arg}"),
            )),
        }
    }

    pub fn parse_reverse_tunnel_arg(arg: &str) -> Result<LocalToRemote, io::Error> {
        let proto = parse_tunnel_arg(arg)?;
        let local_protocol = match proto.local_protocol {
            LocalProtocol::Tcp { .. } => LocalProtocol::ReverseTcp {},
            LocalProtocol::Udp { timeout } => LocalProtocol::ReverseUdp { timeout },
            LocalProtocol::Socks5 { timeout, credentials } => LocalProtocol::ReverseSocks5 { timeout, credentials },
            LocalProtocol::HttpProxy {
                timeout,
                credentials,
                proxy_protocol: _proxy_protocol,
            } => LocalProtocol::ReverseHttpProxy { timeout, credentials },
            LocalProtocol::Unix { path, .. } => LocalProtocol::ReverseUnix { path },
            LocalProtocol::ReverseTcp
            | LocalProtocol::ReverseUdp { .. }
            | LocalProtocol::ReverseSocks5 { .. }
            | LocalProtocol::ReverseHttpProxy { .. }
            | LocalProtocol::ReverseUnix { .. }
            | LocalProtocol::TProxyTcp
            | LocalProtocol::TProxyUdp { .. }
            | LocalProtocol::Stdio { .. } => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Cannot use {:?} as reverse tunnels {}", proto.local_protocol, arg),
                ));
            }
        };

        Ok(LocalToRemote {
            local_protocol,
            local: proto.local,
            remote: proto.remote,
        })
    }

    pub fn parse_sni_override(arg: &str) -> Result<DnsName<'static>, io::Error> {
        match DnsName::try_from(arg.to_string()) {
            Ok(val) => Ok(val),
            Err(err) => Err(io::Error::new(ErrorKind::InvalidInput, format!("Invalid sni override: {err}"))),
        }
    }

    pub fn parse_http_headers(arg: &str) -> Result<(HeaderName, HeaderValue), io::Error> {
        let Some((key, value)) = arg.split_once(':') else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse http header from {arg}"),
            ));
        };

        let value = match HeaderValue::from_str(value.trim()) {
            Ok(value) => value,
            Err(err) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("cannot parse http header value from {value} due to {err:?}"),
                ));
            }
        };

        Ok((HeaderName::from_str(key).unwrap(), value))
    }

    pub fn parse_http_credentials(arg: &str) -> Result<HeaderValue, io::Error> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(arg.trim().as_bytes());
        let Ok(header) = HeaderValue::from_str(&format!("Basic {encoded}")) else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse http credentials {arg}"),
            ));
        };

        Ok(header)
    }

    pub fn parse_server_url(arg: &str) -> Result<Url, io::Error> {
        let Ok(url) = Url::parse(arg) else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("cannot parse server url {arg}"),
            ));
        };

        if !TransportScheme::values().iter().any(|x| x.to_str() == url.scheme()) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("invalid scheme {}", url.scheme()),
            ));
        }

        if url.host().is_none() {
            return Err(io::Error::new(ErrorKind::InvalidInput, format!("invalid server host {arg}")));
        }

        Ok(url)
    }

    #[cfg(test)]
    mod test {
        use super::{LocalToRemote, parse_local_bind, parse_tunnel_arg, parse_tunnel_dest};
        use crate::tunnel::LocalProtocol;
        use collection_macros::btreemap;
        use std::collections::BTreeMap;
        use std::io;
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
        use test_case::test_case;
        use url::Host;

        #[test_case("localhost:443" => (Host::Domain("localhost".to_string()), 443, BTreeMap::new()) ; "with domain")]
        #[test_case("localhost:443?timeout_sec=0" => (Host::Domain("localhost".to_string()), 443, btreemap! { "timeout_sec".to_string() => "0".to_string() } ) ; "with domain and options")]
        #[test_case("127.0.0.1:443" => (Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 443, BTreeMap::new()) ; "with IPv4")]
        #[test_case("[::1]:8080" => (Host::Ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8080, BTreeMap::new()) ; "with IpV6")]
        #[test_case("a:1?timeout_sec=30&b=5" => (Host::Domain("a".to_string()), 1, btreemap! { "b".to_string() => "5".to_string(), "timeout_sec".to_string() => "30".to_string() }) ; "with options")]
        fn test_parse_tunnel_dest(input: &str) -> (Host<String>, u16, BTreeMap<String, String>) {
            parse_tunnel_dest(input).unwrap()
        }

        const LOCALHOST_IP4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443);
        const LOCALHOST_IP6: SocketAddrV6 = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443, 0, 0);

        #[test_case("domain.com:443" => matches Err(_) ; "with domain")]
        #[test_case("127.0.0.1" => matches Err(_) ; "with no port")]
        #[test_case("127.0.0.1:444444443" => matches Err(_) ; "with too long port")]
        #[test_case("127.0.0.1:443" => matches Ok((SocketAddr::V4(LOCALHOST_IP4), _)) ; "with ipv4")]
        #[test_case("[::1]:443" => matches Ok((SocketAddr::V6(LOCALHOST_IP6), _)) ; "with ipv6")]
        fn test_parse_local_bind(input: &str) -> Result<(SocketAddr, &str), io::Error> {
            parse_local_bind(input)
        }

        #[test_case("domain.com:443" => panics ""; "with no protocol")]
        #[test_case("sdsf://443:domain.com:443" => panics ""; "with invalid protocol")]
        #[test_case("tcp://443:domain.com:4443" =>
            LocalToRemote {
                local_protocol: LocalProtocol::Tcp { proxy_protocol: false },
                local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443)),
                remote: (Host::Domain("domain.com".to_string()), 4443),
            }
        ; "with no local bind")]
        #[test_case("udp://[::1]:443:toto.com:4443?timeout_sec=30" =>
            LocalToRemote {
                local_protocol: LocalProtocol::Udp { timeout: Some(std::time::Duration::from_secs(30)) },
                local: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443, 0, 0)),
                remote: (Host::Domain("toto.com".to_string()), 4443),
            }
        ; "with fully defined tunnel")]
        #[test_case("udp://[::1]:443:[::1]:4443?timeout_sec=30" =>
            LocalToRemote {
                local_protocol: LocalProtocol::Udp { timeout: Some(std::time::Duration::from_secs(30)) },
                local: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 443, 0, 0)),
                remote: (Host::Ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 4443),
            }
        ; "with full ipv6 tunnel")]
        fn test_parse_tunnel_arg(input: &str) -> LocalToRemote {
            parse_tunnel_arg(input).unwrap()
        }
    }
}
