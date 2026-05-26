package resolver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Result struct {
	Answers []string
	Raw     *dns.Msg
}

type Resolver interface {
	Resolve(ctx context.Context, domain string, qtype uint16) (*Result, error)
	Protocol() string
	Address() string
}

func New(address string, protocol string, timeout time.Duration) (Resolver, error) {
	switch strings.ToLower(protocol) {
	case "udp":
		return NewUDP(address, timeout), nil
	case "tcp":
		return NewTCP(address, timeout), nil
	case "doh":
		return NewDoH(address, timeout), nil
	case "dot":
		return NewDoT(address, timeout), nil
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func buildQuery(domain string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true
	return msg
}
