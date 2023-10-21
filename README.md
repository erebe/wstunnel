
<p align="center">
  <img src="https://github.com/erebe/wstunnel/raw/main/logo_wstunnel.png" alt="wstunnel logo"/>
</p>

<p align="right">
  <a href="https://ko-fi.com/P5P4QCHMO"><img src="https://ko-fi.com/img/githubbutton_sm.svg"/></a>
</p>


## Description

Most of the time when you are using a public network, you are behind some kind of firewall or proxy. One of their purpose is to constrain you to only use certain kind of protocols. Nowadays, the most widespread protocol is http and is de facto allowed by third party equipment.

This tool understands this fact and uses the websocket protocol which is compatible with http in order to bypass firewalls and proxies. Wstunnel allows you to tunnel what ever traffic you want.

My inspiration came from [this project](https://www.npmjs.com/package/wstunnel) but as I don't want to install npm and nodejs to use this tool, I remade it in Haskell and improved it. 

**What to expect:**

* Good error messages and debug informations
* Static tunneling (TCP and UDP)
* Dynamic tunneling (socks5 proxy)
* Support for http proxy (when behind one)
* Support for tls/https server (with embedded self signed certificate, see comment in the example section)
* Support IPv6
* **Standalone binary for linux x86_64** (so just cp it where you want) [here](https://github.com/erebe/wstunnel/releases)
* Standalone archive for windows

P.S: Please do not pay attention to Main.hs because as I hate to write command line code this file is crappy

## Note

v7.0.0 is a complete rewrite of wstunnel in Rust and is not compatible with previous version.
Previous code in Haskell can be found on branch https://github.com/erebe/wstunnel/tree/haskell

What to expect from previous version:
* More throughput and less jitter due to Haskell GC. Most of you will not care, as it was performant enough already. But you can now saturate a gigabit ethernet card with a single connection
* Command line is more homogeneous/has better UX. All tunnel can be specified multiple times
* Tunnel protocol tries to look like normal traffic, to avoid being flagged
* New bug, it is a rewrite (╯'□')╯︵ ┻━┻ ¯\\_(ツ)_/¯
* Mainly for me to ease the maintenance of the project. I don't do a lot of haskell nowadays and it was harder for me to keep maintening the project over time, as I get lost in touch of the Haskell ecosystem and new release.
* Armv7 build (aka raspberry pi), as new version of GHC (Haskell compiler) dropped its support


## Command line

```
Use the websockets protocol to tunnel {TCP,UDP} traffic
wsTunnelClient <---> wsTunnelServer <---> RemoteHost
Use secure connection (wss://) to bypass proxies

Client:
Usage: wstunnel client [OPTIONS] <ws[s]://wstunnel.server.com[:port]>

Arguments:
  <ws[s]://wstunnel.server.com[:port]>  Address of the wstunnel server
                                        Example: With TLS wss://wstunnel.example.com or without ws://wstunnel.example.com

Options:
  -L, --local-to-remote <{tcp,udp,socks5,stdio}://[BIND:]PORT:HOST:PORT>
          Listen on local and forwards traffic from remote. Can be specified multiple times
          examples:
          'tcp://1212:google.com:443'      =>     listen locally on tcp on port 1212 and forward to google.com on port 443
          'udp://1212:1.1.1.1:53'          =>     listen locally on udp on port 1212 and forward to cloudflare dns 1.1.1.1 on port 53
          'udp://1212:1.1.1.1:53?timeout_sec=10'  timeout_sec on udp force close the tunnel after 10sec. Set it to 0 to disable the timeout [default: 30]
          'socks5://1212'                  =>     listen locally with socks5 on port 1212 and forward dynamically requested tunnel
          'socks5://1212?socket_so_mark=2' =>     each tunnel can have the socket_so_mark option, cf explanation on server command
          'stdio://google.com:443'         =>     listen for data from stdio, mainly for `ssh -o ProxyCommand="wstunnel client -L stdio://%h:%p ws://localhost:8080" my-server`
      --tls-sni-override <DOMAIN_NAME>
          Domain name that will be use as SNI during TLS handshake
          Warning: If you are behind a CDN (i.e: Cloudflare) you must set this domain also in the http HOST header.
                   or it will be flagged as fishy and your request rejected
      --tls-verify-certificate
          Enable TLS certificate verification.
          Disabled by default. The client will happily connect to any server with self signed certificate.
  -p, --http-proxy <http://USER:PASS@HOST:PORT>
          If set, will use this http proxy to connect to the server
      --http-upgrade-path-prefix <HTTP_UPGRADE_PATH_PREFIX>
          Use a specific prefix that will show up in the http path during the upgrade request.
          Useful if you need to route requests server side but don't have vhosts [default: morille]
      --http-upgrade-credentials <USER[:PASS]>
          Pass authorization header with basic auth credentials during the upgrade request.
          If you need more customization, you can use the http_headers option.
      --websocket-ping-frequency-sec <seconds>
          Frequency at which the client will send websocket ping to the server. [default: 30]
      --websocket-mask-frame
          Enable the masking of websocket frames. Default is false
          Enable this option only if you use unsecure (non TLS) websocket server and you see some issues. Otherwise, it is just overhead.
  -H, --http-headers <HEADER_NAME: HEADER_VALUE>
          Send custom headers in the upgrade request
          Can be specified multiple time
  -h, --help
          Print help

Server:
Usage: wstunnel server [OPTIONS] <ws[s]://0.0.0.0[:port]>

Arguments:
  <ws[s]://0.0.0.0[:port]>  Address of the wstunnel server to bind to
                            Example: With TLS wss://0.0.0.0:8080 or without ws://[::]:8080

Options:
      --socket-so-mark <INT>
          (linux only) Mark network packet with SO_MARK sockoption with the specified value.
          You need to use {root, sudo, capabilities} to run wstunnel when using this option
      --websocket-ping-frequency-sec <seconds>
          Frequency at which the server will send websocket ping to client.
      --websocket-mask-frame
          Enable the masking of websocket frames. Default is false
          Enable this option only if you use unsecure (non TLS) websocket server and you see some issues. Otherwise, it is just overhead.
      --restrict-to <DEST:PORT>
          Server will only accept connection from the specified tunnel information.
          Can be specified multiple time
          Example: --restrict-to "google.com:443" --restrict-to "localhost:22"
      --restrict-http-upgrade-path-prefix <RESTRICT_HTTP_UPGRADE_PATH_PREFIX>
          Server will only accept connection from if this specific path prefix is used during websocket upgrade.
          Useful if you specify in the client a custom path prefix and you want the server to only allow this one.
          The path prefix act as a secret to authenticate clients
          Disabled by default. Accept all path prefix
      --tls-certificate <FILE_PATH>
          [Optional] Use custom certificate (.crt) instead of the default embedded self signed certificate.
      --tls-private-key <FILE_PATH>
          [Optional] Use a custom tls key (.key) that the server will use instead of the default embedded one
  -h, --help
          Print help
```

## Release

Static binaries are available in [release section](https://github.com/erebe/wstunnel/releases)

docker image are available at https://github.com/erebe/wstunnel/pkgs/container/wstunnel

```bash
docker pull ghcr.io/erebe/wstunnel:latest
```

## Examples
### Simplest one
On your remote host, start the wstunnel's server by typing this command in your terminal
```bash
wstunnel server ws://[::]:8080
```
This will create a websocket server listening on any interface on port 8080.
On the client side use this command to forward traffic through the websocket tunnel
```bash
wstunnel client -L socks5://8888 ws://myRemoteHost:8080
```
This command will create a sock5 server listening on port 8888 of a loopback interface and will forward traffic.

With firefox you can setup a proxy using this tunnel, by setting in networking preferences 127.0.0.1:8888 and selecting socks5 proxy

or with curl

```bash
curl -x socks5h://127.0.0.1:8888 http://google.com/
#Please note h after the 5, it is to avoid curl resolving DNS name locally
```

### As proxy command for SSH
You can specify `stdio` as source port on the client side if you wish to use wstunnel as part of a proxy command for ssh
```
ssh -o ProxyCommand="wstunnel client -L stdio://%h:%p ws://localhost:8080" my-server
```

### When behind a corporate proxy
An other useful example is when you want to bypass an http proxy (a corporate proxy for example)
The most reliable way to do it is to use wstunnel as described below

Start your wstunnel server with tls activated
```
wstunnel server wss://[::]:443 --restrict-to 127.0.0.1:22
```
The server will listen on any interface using port 443 (https) and restrict traffic to be forwarded only to the ssh daemon.

**Be aware that the server will use self signed certificate with weak cryptographic algorithm.
It was made in order to add the least possible overhead while still being compliant with tls.**

**Do not rely on wstunnel to protect your privacy, as it only forwards traffic that is already secure by design (ex: https)**

Now on the client side start the client with
```
wstunnel client -L tcp://9999:127.0.0.1:22 -p mycorporateproxy:8080 wss://myRemoteHost:443
```
It will start a tcp server on port 9999 that will contact the corporate proxy, negotiate a tls connection with the remote host and forward traffic to the ssh daemon on the remote host.

You may now access your server from your local machine on ssh by using
```
ssh -p 9999 login@127.0.0.1
```

### Wireguard and wstunnel
https://kirill888.github.io/notes/wireguard-via-websocket/

- If you see some throughput issue, be sure to lower the MTU of your wireguard interface (you can do it via config file) to something like 1300 or you will endup fragmenting udp packet (due to overhead of other layer) which is always causing issues
- If wstunnel cannot connect to server while wireguard is on, be sure you have added a static route via your main gateway for the ip of wstunnel server.
Else if you forward all the traffic without putting a static route, you will endup looping your traffic wireguard interface -> wstunnel client -> wireguard interface


## How to Build
Install the Rust https://www.rust-lang.org/tools/install or if you are a believer
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
``` 
and run those commands at the root of the project
```
cargo build
target/debug/wstunnel ...
```

## TODO
- [x] Add sock5 proxy
- [x] Add better logging
- [x] Add better error handling
- [x] Add httpProxy authentification
- [ ] Add Reverse tunnel
- [x] Add more tests for socks5 proxy
