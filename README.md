# wstunnel
```

Use the websockets protocol to tunnel {TCP,UDP} traffic
wsTunnelClient <---> wsTunnelServer <---> RemoteHost
Use secure connection (wss://) to bypass proxies
wstunnel [OPTIONS] ws[s]://wstunnelServer[:port]
Client options:
  -L --localToRemote=[BIND:]PORT:HOST:PORT  Listen on local and forward
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

## TODO
- [ ] Add sock5 proxy
- [x] Add better logging
- [x] Add better error handling
- [x] Add httpProxy authentification
- [ ] Add Reverse tunnel
