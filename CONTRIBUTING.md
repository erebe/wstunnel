# Contributing

## What you need

Building needs a Rust toolchain — the CI pins **1.95.0**, and the crates are on edition 2024.

Beyond that, the checks need:

* [cargo-nextest](https://nexte.st) to run the tests
* a running Docker daemon, as one test spins up a mitmproxy container
* [taplo](https://taplo.tamasfe.dev) to format the TOML files

## Tasks

The repository ships a [justfile](justfile) and a [mise.toml](mise.toml) with the same tasks.
Use whichever tool you already have:

```bash
just fmt          # cargo fmt --all, then taplo fmt
just test         # cargo nextest run
just linter_fix   # cargo clippy --fix
```

```bash
mise run linter-fix   # cargo clippy --fix, then cargo fmt --all
mise run test         # cargo nextest run
```

## Before opening a pull request

CI runs the following on every pull request. Running them locally first saves a round trip:

```bash
cargo fmt --all -- --check
taplo fmt --check
cargo clippy --all --all-features --locked -- -D warnings
cargo nextest run --locked
cargo nextest run --locked --no-default-features --features ring
```

The test suite is run once per crypto provider. `--all-features` does **not** work for it: it
enables both `aws-lc-rs` and `ring`, which forward jsonwebtoken the two providers it treats as
mutually exclusive, and every test going through a tunnel then panics. The providers are
compiled in, never used side by side, so they are tested one at a time.

`ring` is worth running because the armv7, armv6, freebsd and windows-x86 binaries ship with it,
while the default `aws-lc-rs` covers every other platform.

## Reporting an issue

Issues must follow one of the [templates](.github/ISSUE_TEMPLATE); a bot closes the ones that do
not.
