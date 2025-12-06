package upstream

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"

	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Client defines the interface for an upstream DNS resolver.
type Client interface {
	Exchange(m *dns.Msg) (*dns.Msg, error)
}

// NewClient creates a new upstream client based on the address.
// If address starts with "https://", it returns a DoH client.
// Otherwise it returns a standard UDP/TCP client.
func NewClient(address string) (Client, error) {
	if strings.HasPrefix(address, "https://") {
		return &DoHClient{
			URL: address,
			HttpClient: &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: false}, // Set true if needed for testing self-signed
				},
			},
		}, nil
	}

	// Default to standard DNS client
	// Check if port is present, if not add default 53
	if !strings.Contains(address, ":") {
		address = address + ":53"
	}
	return &StandardClient{Address: address}, nil
}

// StandardClient handles UDP and TCP DNS requests.
type StandardClient struct {
	Address string
}

func (s *StandardClient) Exchange(m *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 2 * time.Second // Default timeout

	r, _, err := c.Exchange(m, s.Address)
	if err != nil {
		return nil, err
	}
	
	// If response is truncated, retry with TCP
	if r.Truncated {
		c.Net = "tcp"
		r, _, err = c.Exchange(m, s.Address)
		if err != nil {
			return nil, err
		}
	}
	
	return r, nil
}

// DoHClient handles DNS over HTTPS requests.
type DoHClient struct {
	URL        string
	HttpClient *http.Client
}

func (d *DoHClient) Exchange(m *dns.Msg) (*dns.Msg, error) {
	packed, err := m.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", d.URL, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, err
	}
	
	return r, nil
}
