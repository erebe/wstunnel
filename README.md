
# Wstunnel
## Description

Most of the time when you are using a public network, you are behind some kind of firewall or proxy in order to limit the traffic to only use certain type of protocols, but most of the time http is allowed.

This tool uses the websocket protocol which is compatible with http in order to bypass firewalls and proxies and tunnel what ever traffic you want.

My inspiration went from [this project](https://www.npmjs.com/package/wstunnel) but as I don't want to have to install npm and nodejs to use this tool, I remade it in Haskell and improve it. 

**What to expect :**

* Good error messages and debug informations
* Static tunneling (TCP and UDP)
* Dynamic tunneling (socks5 proxy)
* Support for proxy
* Support for https server (with embeded self signed certificate, see comment in the example section)
* **Standalone binary for linux x86_64** (so just cp it where you want)
* Standalone archive for windows

[Binaries](https://github.com/erebe/wstunnel/tree/master/bin)

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
On the client side use this command to forwards traffic trought the websocket tunnel
```
wstunnel -D 8888 ws://myRemoteHost:8080
```
This command will create a sock5 server listenning only on loopback interface on port 8888 and will forwards traffic.

Ex: With firefox you can setup a proxy using this tunnel by settings in networking preferences 127.0.0.1:8888 and selecting socks5 proxy

### When behind a corporate proxy
An other useful example is when you want to bypass an http proxy (a corporate proxy for example)
The most reliable way to do it is to use wstunnel  as described below

Start your wstunnel server with tls activated
```
wstunnel --server wss://0.0.0.0:443 -r 127.0.0.1:22
```
The server will listen on any interface on port 443 (https) and restrict traffic to be forwarded only to the ssh daemon.

**Be aware that the server will use self signed certificate with weak cryptographic algorithm.
It was made in order to add the least possible overhead while still being compliant with tls.**

**So do not rely on wstunnel to protect your privacy, if you want to do so, forwards only traffic that is already secure by design (ex: https)**

Now on the client side start the client with
```
wstunnel -L 9999:127.0.0.1:22 -p mycorporateproxy:8080 wss://myRemoteHost:443
```
It will start a tcp server on port 9999 that will contact the corporate proxy, negociate a tls connection with the remote host and forward traffic to the ssh daemon on the remote host.

You can now access your server from your local machine on ssh by using
```
ssh -p 9999 login@127.0.0.1
```


## TODO
- [x] Add sock5 proxy
- [x] Add better logging
- [x] Add better error handling
- [x] Add httpProxy authentification
- [ ] Add Reverse tunnel
