package resolver

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

type UDPResolver struct {
	address string
	timeout time.Duration
}

func NewUDP(address string, timeout time.Duration) *UDPResolver {
	return &UDPResolver{address: normalizeAddress(address, "53"), timeout: timeout}
}

func (r *UDPResolver) Resolve(ctx context.Context, domain string, qtype uint16) (*Result, error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: r.timeout,
	}
	msg := buildQuery(domain, qtype)
	resp, _, err := client.ExchangeContext(ctx, msg, r.address)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		client.Net = "tcp"
		resp, _, err = client.ExchangeContext(ctx, msg, r.address)
		if err != nil {
			return nil, err
		}
	}
	return &Result{Answers: ExtractAnswers(resp), Raw: resp}, nil
}

func (r *UDPResolver) Protocol() string { return "udp" }
func (r *UDPResolver) Address() string  { return r.address }
