package resolver

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type AXFRResult struct {
	Records []AXFRRecord
}

type AXFRRecord struct {
	Name  string
	Type  string
	TTL   uint32
	Value string
}

func PerformAXFR(ctx context.Context, server string, domain string, timeout time.Duration) (*AXFRResult, error) {
	server = normalizeAddress(server, "53")

	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(domain))

	transfer := &dns.Transfer{
		DialTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	ch, err := transfer.In(msg, server)
	if err != nil {
		return nil, fmt.Errorf("AXFR initiation failed for %s: %w", domain, err)
	}

	result := &AXFRResult{}
	for envelope := range ch {
		if envelope.Error != nil {
			if len(result.Records) > 0 {
				break
			}
			return nil, fmt.Errorf("AXFR transfer error: %w", envelope.Error)
		}
		for _, rr := range envelope.RR {
			typeName := dns.TypeToString[rr.Header().Rrtype]
			values := extractRR(rr)
			value := rr.String()
			if len(values) > 0 {
				value = values[0]
			}
			result.Records = append(result.Records, AXFRRecord{
				Name:  rr.Header().Name,
				Type:  typeName,
				TTL:   rr.Header().Ttl,
				Value: value,
			})
		}
	}

	if len(result.Records) == 0 {
		return nil, fmt.Errorf("AXFR returned no records for %s (zone transfer may be denied)", domain)
	}

	return result, nil
}
