//! Drives a connection attempt across HTTP redirects.
//!
//! Both TCP transports (`websocket` and `http2`) need the same bookkeeping around a redirect chain:
//! hop accounting, cycle detection, the permanent/temporary rule, updating the shared active target,
//! and falling back to the canonical server URL when a cached target stops working. Only the
//! transport-specific parts — building the upgrade request and performing the handshake — differ, so
//! they are supplied by the caller as a "hop" callback.
//!
//! See `docs/server_url_redirection.md` for the behaviour this implements, including §2.4 on how
//! redirects interact with the connection pool.

use crate::executor::TokioExecutorRef;
use crate::tunnel::client::Client;
use crate::tunnel::client::connection_pool::{L4Stream, connect_l4_stream};
use crate::tunnel::transport::TransportAddr;
use anyhow::{Context, anyhow};
use either::Either;
use hyper::header::{AUTHORIZATION, COOKIE, LOCATION, PROXY_AUTHORIZATION};
use hyper::{HeaderMap, StatusCode};
use log::{debug, info, warn};
use std::collections::HashSet;
use std::future::Future;

/// What a single hop of a connection attempt produced.
pub(crate) enum HopOutcome<T> {
    /// The handshake succeeded and the transport is ready to carry the tunnel.
    Connected(T),
    /// The server answered with a redirection status; the caller supplies the response headers so
    /// the chain logic can read `Location` (and later, cache directives) in one place.
    Redirect { status: StatusCode, headers: HeaderMap },
}

/// What the chain knows about the hop a callback is about to perform, so it can decide which of the
/// user's headers still apply. The rules follow curl:
///
/// - A `Host`/authority the user pinned stays in effect as long as the hop is on the same *host*
///   (a different port or path is still the same service), and is derived from the new address once
///   the host changes.
/// - Credentials are scoped to the *origin* (scheme + host + port) they were configured for and are
///   not forwarded to another origin unless the user opted in with `--forward-credentials-on-redirect`
///   (curl's `--location-trusted`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct HopPolicy {
    /// Whether a user-pinned `Host`/authority still applies to this hop.
    pub(crate) keep_pinned_host: bool,
    /// Whether credentials (`Authorization`, cookies, `Proxy-Authorization`) may be sent to this hop.
    pub(crate) keep_credentials: bool,
}

impl HopPolicy {
    /// Whether `name` may be sent to this hop. Only the credentials above are origin scoped; every
    /// other header the user configured is forwarded, as curl does.
    pub(crate) fn allows_header(&self, name: &hyper::header::HeaderName) -> bool {
        self.keep_credentials || !(name == AUTHORIZATION || name == COOKIE || name == PROXY_AUTHORIZATION)
    }
}

/// Connects to the server of `client`, following redirects, and returns what the hop callback
/// produced for the hop that finally succeeded.
///
/// A connection attempt starts either at the configured server URL or at the target cached by an
/// earlier, fully permanent redirect chain. If the cached target fails, the attempt is retried once
/// against the configured URL and the cache is dropped, so a rotated or restarted target heals
/// itself.
pub(crate) async fn connect<T, E, F, Fut>(client: &Client<E>, hop: F) -> anyhow::Result<T>
where
    E: TokioExecutorRef,
    F: FnMut(L4Stream, TransportAddr, String, HopPolicy) -> Fut,
    Fut: Future<Output = anyhow::Result<HopOutcome<T>>>,
{
    let client_cfg = &client.config;
    let active = client.active_target();
    let is_cached = !active.is_same_target(&client_cfg.remote_addr, &client_cfg.http_upgrade_path_prefix);

    if is_cached {
        let mut hop = hop;
        match attempt(client, false, active.addr.clone(), active.path_prefix.clone(), &mut hop).await {
            Ok(res) => Ok(res),
            Err(err) => {
                warn!(
                    "Failed to connect to cached redirect target {:?}: {:?}. Falling back to canonical server URL {:?}",
                    active.addr, err, client_cfg.remote_addr
                );
                client.reset_active_target();
                // When falling back after a cached target failure, establish a fresh L4 connection
                // directly rather than borrowing potentially stale/closed sockets from the pool.
                attempt(
                    client,
                    false,
                    client_cfg.remote_addr.clone(),
                    client_cfg.http_upgrade_path_prefix.clone(),
                    &mut hop,
                )
                .await
            }
        }
    } else {
        let mut hop = hop;
        attempt(
            client,
            true,
            client_cfg.remote_addr.clone(),
            client_cfg.http_upgrade_path_prefix.clone(),
            &mut hop,
        )
        .await
    }
}

/// Follows the redirect chain for one attempt, starting at `start_addr`.
///
/// `hop` receives the freshly established L4 stream, the address to talk to, the path prefix to use
/// and whether this is the first hop of the attempt (which is the only hop allowed to take a
/// connection from the pool).
async fn attempt<T, E, F, Fut>(
    client: &Client<E>,
    can_use_pool: bool,
    start_addr: TransportAddr,
    start_path_prefix: String,
    hop: &mut F,
) -> anyhow::Result<T>
where
    E: TokioExecutorRef,
    F: FnMut(L4Stream, TransportAddr, String, HopPolicy) -> Fut,
    Fut: Future<Output = anyhow::Result<HopOutcome<T>>>,
{
    let client_cfg = &client.config;
    let mut current_addr = start_addr;
    let mut current_path_prefix = start_path_prefix;
    let mut visited = HashSet::new();
    let max_redirects = client_cfg.max_redirects;
    let mut redirect_count = 0;
    let mut is_permanent_chain = true;

    loop {
        let is_initial = redirect_count == 0;

        // The connection pool (cnx_pool) maintains pre-warmed L4 connections exclusively
        // to the canonical configured server URL (client_cfg.remote_addr).
        // Therefore, pooled connections can only be utilized on the initial attempt (redirect_count == 0)
        // when dialing the canonical address. All redirected hops or connections to an updated active_target
        // deliberately bypass the pool and establish a fresh L4 connection directly to the destination.
        // Trade-off (redirected tunnels are not pre-warmed, the pool keeps filling the canonical
        // URL): see "Connection pooling and redirects" in docs/server_url_redirection.md.
        let transport = if can_use_pool && is_initial {
            let mut pooled_cnx = match client.cnx_pool.get().await {
                Ok(cnx) => Ok(cnx),
                Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
            }?;
            pooled_cnx
                .take()
                .and_then(Either::left)
                .ok_or_else(|| anyhow!("the connection pool did not return a TCP stream"))?
        } else {
            connect_l4_stream(client_cfg, &current_addr).await?
        };

        let policy = {
            let configured = &client_cfg.remote_addr;
            HopPolicy {
                keep_pinned_host: current_addr.host() == configured.host(),
                keep_credentials: current_addr.is_same_endpoint(configured)
                    || client_cfg.forward_credentials_on_redirect,
            }
        };

        match hop(transport, current_addr.clone(), current_path_prefix.clone(), policy).await? {
            HopOutcome::Connected(value) => {
                // In accordance with RFC 9110, only permanent redirects (301/308) update the client's
                // active target across connections. Temporary redirects (302/307) are not cached.
                if redirect_count > 0 {
                    if is_permanent_chain {
                        info!("Permanently updated active target to {current_addr:?}");
                        debug!("Active target path prefix: {current_path_prefix:?}");
                        client.set_active_target(current_addr, current_path_prefix);
                    } else {
                        // A temporary hop means any previously cached permanent target is no longer
                        // authoritative: drop it so the next connection re-resolves from the canonical
                        // server URL instead of keeping the stale hop alive until it fails.
                        client.reset_active_target();
                    }
                }
                return Ok(value);
            }
            HopOutcome::Redirect { status, headers } => {
                if redirect_count >= max_redirects {
                    return Err(if max_redirects == 0 {
                        anyhow!(
                            "redirect following is disabled (max_redirects = 0) when connecting to {:?}",
                            client_cfg.remote_addr
                        )
                    } else {
                        anyhow!(
                            "exceeded maximum of {max_redirects} redirects when connecting to {:?}",
                            client_cfg.remote_addr
                        )
                    });
                }
                redirect_count += 1;

                let hop_is_permanent = matches!(status, StatusCode::MOVED_PERMANENTLY | StatusCode::PERMANENT_REDIRECT);
                if !hop_is_permanent {
                    is_permanent_chain = false;
                }

                let location = headers
                    .get(LOCATION)
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(|| anyhow!("Redirect status code {status} without valid Location header"))?
                    .to_string();

                let (next_addr, next_prefix) = current_addr
                    .resolve_redirect(&current_path_prefix, &location, &mut visited, client_cfg.tls_verify_certificate)
                    .with_context(|| format!("failed to follow redirect from {current_addr:?} to {location}"))?;

                // The full target URL can be long and may carry deployment specific paths, so it goes
                // to debug; at info level only the origin we switch to is reported.
                info!("Server redirected ({status}) to {next_addr:?}");
                debug!("Redirect location {location} resolved to path prefix {next_prefix:?}");

                current_addr = next_addr;
                current_path_prefix = next_prefix;
            }
        }
    }
}
