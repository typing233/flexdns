package wildcard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/flexdns/flexdns/pkg/resolver"
	"github.com/miekg/dns"
)

type Detector struct {
	resolver    resolver.Resolver
	domain      string
	wildcardIPs map[string]struct{}
	HasWildcard bool
}

func NewDetector(r resolver.Resolver, domain string) *Detector {
	return &Detector{
		resolver:    r,
		domain:      domain,
		wildcardIPs: make(map[string]struct{}),
	}
}

func (d *Detector) Detect(ctx context.Context) error {
	ipCounts := make(map[string]int)
	const probes = 5

	for i := 0; i < probes; i++ {
		randSub := randomPrefix() + "." + d.domain
		result, err := d.resolver.Resolve(ctx, randSub, dns.TypeA)
		if err != nil {
			continue
		}
		for _, ans := range result.Answers {
			ipCounts[ans]++
		}
	}

	for ip, count := range ipCounts {
		if count >= 3 {
			d.wildcardIPs[ip] = struct{}{}
			d.HasWildcard = true
		}
	}
	return nil
}

func (d *Detector) IsWildcard(answers []string) bool {
	if !d.HasWildcard || len(answers) == 0 {
		return false
	}
	for _, ans := range answers {
		if _, ok := d.wildcardIPs[ans]; !ok {
			return false
		}
	}
	return true
}

func (d *Detector) WildcardIPs() []string {
	ips := make([]string, 0, len(d.wildcardIPs))
	for ip := range d.wildcardIPs {
		ips = append(ips, ip)
	}
	return ips
}

func randomPrefix() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("wc-%s", hex.EncodeToString(b))
}
