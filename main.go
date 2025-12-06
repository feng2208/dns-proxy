package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"dns-proxy/config"
	"dns-proxy/server"
	"dns-proxy/upstream"

	"github.com/miekg/dns"
)

func main() {
	port := flag.Int("port", 53, "DNS server listening port")
	upstreamAddr := flag.String("upstream", "8.8.8.8:53", "Upstream DNS server address (UDP/TCP or https:// for DoH)")
	domainListPath := flag.String("domain-list", "domains.json", "Path to JSON file containing whitelist and blacklist")
	ipListPath := flag.String("ip-list", "ips.txt", "Path to file containing allowed CIDR list")
	fallbackIPStr := flag.String("fallback-ip", "127.0.0.1", "Fallback IP address to return when blocked or IP check fails")
	minTTL := flag.Uint("min-ttl", 20, "Minimum TTL for DNS responses")

	flag.Parse()

	// Parse Fallback IP
	fallbackIP := net.ParseIP(*fallbackIPStr)
	if fallbackIP == nil {
		log.Fatalf("Invalid fallback IP: %s", *fallbackIPStr)
	}
	if v4 := fallbackIP.To4(); v4 != nil {
		fallbackIP = v4
	}

	// Load Domain Config
	domainConfig, err := config.LoadDomainConfig(*domainListPath)
	if err != nil {
		log.Printf("Warning: Failed to load domain list from %s: %v. Proceeding with empty lists.", *domainListPath, err)
		domainConfig = &config.Config{
			Whitelist: make(map[string]struct{}),
			Blacklist: make(map[string]struct{}),
		}
	}

	// Load IP List
	if err := domainConfig.LoadIPList(*ipListPath); err != nil {
		log.Printf("Warning: Failed to load IP list from %s: %v. Proceeding with empty allowlist (block all non-whitelisted if logic dictates).", *ipListPath, err)
	}

	// Setup Upstream Client
	upstreamClient, err := upstream.NewClient(*upstreamAddr)
	if err != nil {
		log.Fatalf("Failed to create upstream client: %v", err)
	}

	// Setup Handler
	handler := &server.DNSHandler{
		Config:     domainConfig,
		Upstream:   upstreamClient,
		FallbackIP: fallbackIP,
		MinTTL:     uint32(*minTTL),
	}

	// Start Servers
	addr := ":" + strconv.Itoa(*port)
	udpServer := &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	go func() {
		log.Printf("Starting UDP server on %s", addr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %v", err)
		}
	}()

	go func() {
		log.Printf("Starting TCP server on %s", addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start TCP server: %v", err)
		}
	}()

	// Wait for signal to shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down servers...")
	udpServer.Shutdown()
	tcpServer.Shutdown()
}
