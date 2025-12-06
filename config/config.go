package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// DomainConfig holds the whitelist and blacklist domains.
type DomainConfig struct {
	Whitelist []string `json:"whitelist"`
	Blacklist []string `json:"blacklist"`
}

// Config holds the runtime configuration.
type Config struct {
	Whitelist  map[string]struct{}
	Blacklist  map[string]struct{}
	AllowedIPs []*net.IPNet
}

// LoadDomainConfig loads whitelist and blacklist from a JSON file.
// Returns a Config object with the domains populated in maps for O(1) lookup.
func LoadDomainConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open domain config file: %w", err)
	}
	defer file.Close()

	var dc DomainConfig
	if err := json.NewDecoder(file).Decode(&dc); err != nil {
		return nil, fmt.Errorf("failed to decode domain config: %w", err)
	}

	cfg := &Config{
		Whitelist: make(map[string]struct{}),
		Blacklist: make(map[string]struct{}),
	}

	for _, d := range dc.Whitelist {
		cfg.Whitelist[strings.ToLower(d)] = struct{}{}
		// Add trailing dot if not present, as DNS queries often have it
		if !strings.HasSuffix(d, ".") {
			cfg.Whitelist[strings.ToLower(d)+"."] = struct{}{}
		}
	}
	for _, d := range dc.Blacklist {
		cfg.Blacklist[strings.ToLower(d)] = struct{}{}
		if !strings.HasSuffix(d, ".") {
			cfg.Blacklist[strings.ToLower(d)+"."] = struct{}{}
		}
	}

	return cfg, nil
}

// LoadIPList loads a list of CIDRs from a file.
func (c *Config) LoadIPList(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open IP list file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			// Try parsing as single IP
			ip := net.ParseIP(line)
			if ip != nil {
				if ip4 := ip.To4(); ip4 != nil {
					network = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
				} else {
					network = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
				}
			} else {
				// Log or ignore invalid CIDR? For now we'll error out or maybe just skip?
				// User said "format is every line one CIDR", strictly.
				// But robust code should handle errors. Let's return error to be safe.
				return fmt.Errorf("invalid CIDR or IP in list: %s", line)
			}
		}
		c.AllowedIPs = append(c.AllowedIPs, network)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading IP list file: %w", err)
	}

	return nil
}

// IsIPAllowed checks if the given IP is in the AllowedIPs list.
func (c *Config) IsIPAllowed(ip net.IP) bool {
	for _, net := range c.AllowedIPs {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}
