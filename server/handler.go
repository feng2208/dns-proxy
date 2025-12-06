package server

import (
	"log"
	"net"
	"strings"

	"dns-proxy/config"
	"dns-proxy/upstream"

	"github.com/miekg/dns"
)

type DNSHandler struct {
	Config     *config.Config
	Upstream   upstream.Client
	FallbackIP net.IP
	MinTTL     uint32
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(msg)
		return
	}

	q := r.Question[0]
	qName := strings.ToLower(q.Name)

	// Requirement 1 & 2: Handle only A and AAAA.
	// Requirement 2: Return error for AAAA.
	if q.Qtype == dns.TypeAAAA {
		msg.Rcode = dns.RcodeRefused // Or dns.RcodeNotImplemented
		w.WriteMsg(msg)
		return
	}

	// For non-A types, just forward to upstream.
	if q.Qtype != dns.TypeA {
		h.forward(w, r)
		return
	}

	// Requirement 3: Handle A Request
	// a: Check Whitelist
	if h.matchDomain(qName, h.Config.Whitelist) {
		log.Printf("[WhiteList] Allowed: %s", qName)
		h.forwardWithTTLFix(w, r)
		return
	}

	// b: Check Blacklist
	if h.matchDomain(qName, h.Config.Blacklist) {
		log.Printf("[BlackList] Blocked: %s, returning fallback IP", qName)
		h.respondWithFallbackIP(w, r)
		return
	}

	// c: Default case - Upstream then check IP
	resp, err := h.Upstream.Exchange(r)
	if err != nil {
		log.Printf("Upstream error: %v", err)
		dns.HandleFailed(w, r)
		return
	}

	// Check returned IPs
	allIPsAllowed := true
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			if !h.Config.IsIPAllowed(a.A) {
				allIPsAllowed = false
				break
			}
		}
	}

	if !allIPsAllowed {
		log.Printf("[IP Check] Failed for %s. Returning fallback IP", qName)
		h.respondWithFallbackIP(w, r)
		return
	}

	// Pass through with TTL fix
	h.applyMinTTL(resp)
	w.WriteMsg(resp)
}

func (h *DNSHandler) forward(w dns.ResponseWriter, r *dns.Msg) {
	resp, err := h.Upstream.Exchange(r)
	if err != nil {
		log.Printf("Upstream error processing %s: %v", r.Question[0].Name, err)
		dns.HandleFailed(w, r)
		return
	}
	w.WriteMsg(resp)
}

func (h *DNSHandler) forwardWithTTLFix(w dns.ResponseWriter, r *dns.Msg) {
	resp, err := h.Upstream.Exchange(r)
	if err != nil {
		log.Printf("Upstream error processing %s: %v", r.Question[0].Name, err)
		dns.HandleFailed(w, r)
		return
	}
	h.applyMinTTL(resp)
	w.WriteMsg(resp)
}

func (h *DNSHandler) respondWithFallbackIP(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	
	q := r.Question[0]
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    h.MinTTL, // Use MinTTL for synthesized response
		},
		A: h.FallbackIP,
	}
	msg.Answer = append(msg.Answer, rr)
	w.WriteMsg(msg)
}

func (h *DNSHandler) applyMinTTL(m *dns.Msg) {
	for _, rr := range m.Answer {
		if rr.Header().Ttl < h.MinTTL {
			rr.Header().Ttl = h.MinTTL
		}
	}
	for _, rr := range m.Ns {
		if rr.Header().Ttl < h.MinTTL {
			rr.Header().Ttl = h.MinTTL
		}
	}
	for _, rr := range m.Extra {
		if rr.Header().Ttl < h.MinTTL {
			rr.Header().Ttl = h.MinTTL
		}
	}
}

// matchDomain checks if the domain or any of its parent domains exist in the list.
// The domain is expected to be fully qualified (ending with .).
func (h *DNSHandler) matchDomain(domain string, list map[string]struct{}) bool {
	// Loop through parent domains
	// example: a.b.c. -> check a.b.c. then b.c. then c.
	current := domain
	for {
		if _, ok := list[current]; ok {
			return true
		}
		
		// Find next dot
		idx := strings.Index(current, ".")
		if idx == -1 || idx == len(current)-1 {
			// reached tld or root. If we want to match exact TLD (like com.), it would be in list.
			// The loop should break if we can't split further effectively.
			break
		}
		current = current[idx+1:]
	}
	return false
}
