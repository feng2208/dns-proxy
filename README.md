# dns-proxy

## 运行
```
Usage of ./dns-proxy:
  -domain-list string
    	Path to JSON file containing whitelist and blacklist (default "domains.json")
  -fallback-ip string
    	Fallback IP address to return when blocked or IP check fails (default "127.0.0.1")
  -ip-list string
    	Path to file containing allowed CIDR list (default "ips.txt")
  -min-ttl uint
    	Minimum TTL for DNS responses (default 20)
  -port int
    	DNS server listening port (default 53)
  -upstream string
    	Upstream DNS server address (UDP/TCP or https:// for DoH) (default "8.8.8.8:53")
```


## How to build
Prerequisites
Go 1.21 or later installed.

Build:
```
go build -o dns-proxy .
```

Run:
```
./dns-proxy -port 5354 -domain-list domains.json -ip-list ips.txt -upstream 8.8.8.8:53 -fallback-ip 1.2.3.4
```
