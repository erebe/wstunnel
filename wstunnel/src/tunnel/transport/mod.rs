use hyper::header::HOST;
use hyper::http::{HeaderName, HeaderValue};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

use tracing::error;

pub mod http2;
pub mod io;
mod jwt;
mod types;
pub mod websocket;

pub use jwt::JWT_HEADER_PREFIX;
pub use jwt::JwtTunnelConfig;
pub use jwt::jwt_token_to_tunnel;
pub use jwt::tunnel_to_jwt_token;
pub use types::TransportAddr;
pub use types::TransportScheme;

#[allow(clippy::type_complexity)]
#[inline]
pub fn headers_from_file(path: &Path) -> (Option<(HeaderName, HeaderValue)>, Vec<(HeaderName, HeaderValue)>) {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            error!("Cannot read headers from file: {:?}: {:?}", path, err);
            return (None, vec![]);
        }
    };

    let mut host_header = None;
    let headers = BufReader::new(file)
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let (header, value) = line.split_once(':')?;
            let header = HeaderName::from_str(header.trim()).ok()?;
            let value = HeaderValue::from_str(value.trim()).ok()?;
            if header == HOST {
                host_header = Some((header, value));
                return None;
            }
            Some((header, value))
        })
        .collect();

    (host_header, headers)
}
