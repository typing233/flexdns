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

	var asn string
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
			asn = parseASNumber(txt.Txt[0])
			break
		}
	}
	if asn == "" {
		return nil
	}

	info := &ASNInfo{ASN: "AS" + asn}
	info.Desc = lookupASName(ctx, asn, client)
	return info
}

func lookupASName(ctx context.Context, asn string, client *dns.Client) string {
	queryDomain := fmt.Sprintf("AS%s.asn.cymru.com.", asn)
	msg := new(dns.Msg)
	msg.SetQuestion(queryDomain, dns.TypeTXT)
	msg.RecursionDesired = true

	resp, _, err := client.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil || resp == nil || len(resp.Answer) == 0 {
		return ""
	}

	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
			return parseASNameFromTXT(txt.Txt[0])
		}
	}
	return ""
}

func parseASNumber(txt string) string {
	parts := strings.Split(txt, "|")
	if len(parts) < 1 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func parseASNameFromTXT(txt string) string {
	// Format: "ASN | CC | Registry | Allocated | AS Name"
	parts := strings.Split(txt, "|")
	if len(parts) >= 5 {
		return strings.TrimSpace(parts[4])
	}
	return ""
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
