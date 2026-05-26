package resolver

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/miekg/dns"
)

type DoTResolver struct {
	address string
	host    string
	timeout time.Duration
}

func NewDoT(address string, timeout time.Duration) *DoTResolver {
	host, _ := splitHostPort(address)
	return &DoTResolver{
		address: normalizeAddress(address, "853"),
		host:    host,
		timeout: timeout,
	}
}

func (r *DoTResolver) Resolve(ctx context.Context, domain string, qtype uint16) (*Result, error) {
	client := &dns.Client{
		Net:     "tcp-tls",
		Timeout: r.timeout,
		TLSConfig: &tls.Config{
			ServerName: r.host,
		},
	}
	msg := buildQuery(domain, qtype)
	resp, _, err := client.ExchangeContext(ctx, msg, r.address)
	if err != nil {
		return nil, err
	}
	return &Result{Answers: ExtractAnswers(resp, qtype), Raw: resp}, nil
}

func (r *DoTResolver) Protocol() string { return "dot" }
func (r *DoTResolver) Address() string  { return r.address }
