#[cfg(unix)]
mod server_unix;
#[cfg(not(unix))]
mod server_windows;

#[cfg(unix)]
pub use server_unix::run_server;
#[cfg(not(unix))]
pub use server_windows::run_server;
