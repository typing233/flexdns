package cdn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type ASNInfo struct {
	ASN  string `json:"asn"`
	Desc string `json:"desc"`
}

func LookupASN(ctx context.Context, ip string, timeout time.Duration) *ASNInfo {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}

	var queryDomain string
	if parsed.To4() != nil {
		parts := strings.Split(ip, ".")
		queryDomain = fmt.Sprintf("%s.%s.%s.%s.origin.asn.cymru.com.",
			parts[3], parts[2], parts[1], parts[0])
	} else {
		expanded := expandIPv6(parsed)
		reversed := reverseNibbles(expanded)
		queryDomain = reversed + ".origin6.asn.cymru.com."
	}

	client := &dns.Client{Net: "udp", Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(queryDomain, dns.TypeTXT)
	msg.RecursionDesired = true

	resp, _, err := client.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil || resp == nil || len(resp.Answer) == 0 {
		return nil
	}

	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
			return parseASNResponse(txt.Txt[0])
		}
	}
	return nil
}

func parseASNResponse(txt string) *ASNInfo {
	parts := strings.Split(txt, "|")
	if len(parts) < 1 {
		return nil
	}
	asn := strings.TrimSpace(parts[0])
	if asn == "" {
		return nil
	}

	info := &ASNInfo{ASN: "AS" + asn}
	if len(parts) >= 5 {
		info.Desc = strings.TrimSpace(parts[4])
	}
	return info
}

func expandIPv6(ip net.IP) string {
	ip = ip.To16()
	var sb strings.Builder
	for i, b := range ip {
		if i > 0 && i%2 == 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(fmt.Sprintf("%02x", b))
	}
	return sb.String()
}

func reverseNibbles(expanded string) string {
	clean := strings.ReplaceAll(expanded, ":", "")
	var sb strings.Builder
	for i := len(clean) - 1; i >= 0; i-- {
		sb.WriteByte(clean[i])
		if i > 0 {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
