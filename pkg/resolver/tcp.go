package resolver

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

type TCPResolver struct {
	address string
	timeout time.Duration
}

func NewTCP(address string, timeout time.Duration) *TCPResolver {
	return &TCPResolver{address: normalizeAddress(address, "53"), timeout: timeout}
}

func (r *TCPResolver) Resolve(ctx context.Context, domain string, qtype uint16) (*Result, error) {
	client := &dns.Client{
		Net:     "tcp",
		Timeout: r.timeout,
	}
	msg := buildQuery(domain, qtype)
	resp, _, err := client.ExchangeContext(ctx, msg, r.address)
	if err != nil {
		return nil, err
	}
	return &Result{Answers: ExtractAnswers(resp, qtype), Raw: resp}, nil
}

func (r *TCPResolver) Protocol() string { return "tcp" }
func (r *TCPResolver) Address() string  { return r.address }
