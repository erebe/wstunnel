
<p align="center">
  <img src="https://github.com/erebe/wstunnel/raw/master/logo_wstunnel.png" alt="wstunnel logo"/>
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
* Support for tls/https server (with embeded self signed certificate, see comment in the example section)
* **Standalone binary for linux x86_64** (so just cp it where you want)
* Standalone archive for windows

[Binaries](https://github.com/erebe/wstunnel/releases/tag/2.0)

P.S: Please do not pay attention to Main.hs because as I hate to write command line code this file is crappy

## Command line

```
Use the websockets protocol to tunnel {TCP,UDP} traffic
wsTunnelClient <---> wsTunnelServer <---> RemoteHost
Use secure connection (wss://) to bypass proxies

wstunnel [OPTIONS] ws[s]://wstunnelServer[:port]
Client options:
  -L --localToRemote=[BIND:]PORT:HOST:PORT  Listen on local and forwards
                                            traffic from remote
  -D --dynamicToRemote=[BIND:]PORT          Listen on local and dynamically
                                            (with socks5 proxy) forwards
                                            traffic from remote
  -u --udp                                  forward UDP traffic instead of
                                            TCP
  -p --httpProxy=USER:PASS@HOST:PORT        If set, will use this proxy to
                                            connect to the server
Server options:
     --server                               Start a server that will forward
                                            traffic for you
  -r --restrictTo=HOST:PORT                 Accept traffic to be forwarded
                                            only to this service
Common options:
  -v --verbose                              Print debug information
  -q --quiet                                Print only errors
  -h --help                                 Display help message
  -V --version                              Print version information
```

## Examples
### Simplest one
On your remote host, start the wstunnel's server by typing this command in your terminal
```
wstunnel --server ws://0.0.0.0:8080
```
This will create a websocket server listenning on any interface on port 8080.
On the client side use this command to forward traffic through the websocket tunnel
```
wstunnel -D 8888 ws://myRemoteHost:8080
```
This command will create a sock5 server listening on port 8888 of a loopback interface and will forward traffic.

Ex: With firefox you can setup a proxy using this tunnel, by setting in networking preferences 127.0.0.1:8888 and selecting socks5 proxy

### As proxy command for SSH
You can specify `stdio` as source port on the client side if you wish to use wstunnel as part of a proxy command for ssh
```
ssh -o ProxyCommand="wstunnel -L stdio:%h:%p ws://localhost:8080" my-server
```

### When behind a corporate proxy
An other useful example is when you want to bypass an http proxy (a corporate proxy for example)
The most reliable way to do it is to use wstunnel as described below

Start your wstunnel server with tls activated
```
wstunnel --server wss://0.0.0.0:443 -r 127.0.0.1:22
```
The server will listen on any interface using port 443 (https) and restrict traffic to be forwarded only to the ssh daemon.

**Be aware that the server will use self signed certificate with weak cryptographic algorithm.
It was made in order to add the least possible overhead while still being compliant with tls.**

**Do not rely on wstunnel to protect your privacy, as it only forwards traffic that is already secure by design (ex: https)**

Now on the client side start the client with
```
wstunnel -L 9999:127.0.0.1:22 -p mycorporateproxy:8080 wss://myRemoteHost:443
```
It will start a tcp server on port 9999 that will contact the corporate proxy, negotiate a tls connection with the remote host and forward traffic to the ssh daemon on the remote host.

You may now access your server from your local machine on ssh by using
```
ssh -p 9999 login@127.0.0.1
```

### Wireguard and wstunnel
https://kirill888.github.io/notes/wireguard-via-websocket/


## How to Build
Install the stack tool https://docs.haskellstack.org/en/stable/README/ or if you are a believer
```
curl -sSL https://get.haskellstack.org/ | sh
``` 
and run those commands at the root of the project
```
stack init
stack install
```

## TODO
- [x] Add sock5 proxy
- [x] Add better logging
- [x] Add better error handling
- [x] Add httpProxy authentification
- [ ] Add Reverse tunnel
- [ ] Add more tests for socks5 proxy
