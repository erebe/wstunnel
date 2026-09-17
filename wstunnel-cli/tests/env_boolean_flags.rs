//! Regression tests for boolean flags set through the environment.
//!
//! clap's default value parser only accepts the literals `true`/`false`, so `NO_COLOR=1` (the value
//! the convention documents) and an empty `NO_COLOR=` used to abort the CLI with a parse error.

use std::process::Command;

/// Runs `wstunnel client <unreachable url>` with one extra environment variable. With no tunnel to
/// establish the client exits immediately, which makes this a pure argument-parsing test.
fn run_with_env(name: &str, value: &str) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wstunnel"))
        .args(["client", "ws://127.0.0.1:1"])
        // Keep an ambient NO_COLOR from leaking into the tests of the other flag.
        .env_remove("NO_COLOR")
        .env(name, value)
        .output()
        .expect("failed to run wstunnel");

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

#[test]
fn no_color_env_accepts_the_usual_values() {
    for value in ["1", "true", "yes", "on", "ON"] {
        let (ok, out) = run_with_env("NO_COLOR", value);
        assert!(ok, "NO_COLOR={value} must not abort the CLI: {out}");
        assert!(!out.contains('\u{1b}'), "NO_COLOR={value} should disable colors: {out}");
    }

    // Falsy values, including the "set but empty" case the convention says to ignore, keep colors on.
    for value in ["0", "false", "no", "off", ""] {
        let (ok, out) = run_with_env("NO_COLOR", value);
        assert!(ok, "NO_COLOR={value} must not abort the CLI: {out}");
        assert!(out.contains('\u{1b}'), "NO_COLOR={value} should keep colors: {out}");
    }
}

#[test]
fn dns_prefer_ipv4_env_accepts_the_usual_values() {
    for value in ["1", "0", "true", "false", "yes", "no", "on", "off"] {
        let (ok, out) = run_with_env("WSTUNNEL_DNS_PREFER_IPV4", value);
        assert!(ok, "WSTUNNEL_DNS_PREFER_IPV4={value} must not abort the CLI: {out}");
    }
}

#[test]
fn nonsense_boolean_env_still_reports_a_parse_error() {
    let (ok, out) = run_with_env("NO_COLOR", "banane");
    assert!(!ok, "a nonsense value must still fail: {out}");
    assert!(out.contains("cannot parse boolean from banane"), "{out}");
}
