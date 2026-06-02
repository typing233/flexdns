package resolver

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

var TypeMap = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"CNAME": dns.TypeCNAME,
	"NS":    dns.TypeNS,
	"MX":    dns.TypeMX,
	"TXT":   dns.TypeTXT,
	"PTR":   dns.TypePTR,
	"SOA":   dns.TypeSOA,
	"SRV":   dns.TypeSRV,
	"CAA":   dns.TypeCAA,
	"ANY":   dns.TypeANY,
}

var AllTypes = []string{"A", "AAAA", "CNAME", "NS", "MX", "TXT", "PTR", "SOA", "SRV", "CAA"}

func ParseType(s string) (uint16, bool) {
	t, ok := TypeMap[strings.ToUpper(s)]
	return t, ok
}

func ExpandRecordTypes(types []string, excludes []string) []string {
	excludeSet := make(map[string]struct{})
	for _, e := range excludes {
		excludeSet[strings.ToUpper(strings.TrimSpace(e))] = struct{}{}
	}

	var result []string
	for _, t := range types {
		t = strings.ToUpper(strings.TrimSpace(t))
		if t == "ALL" {
			for _, at := range AllTypes {
				if _, excluded := excludeSet[at]; !excluded {
					result = append(result, at)
				}
			}
		} else {
			if _, excluded := excludeSet[t]; !excluded {
				result = append(result, t)
			}
		}
	}
	return result
}

func ExtractAnswers(msg *dns.Msg, qtype uint16) []string {
	var answers []string
	for _, rr := range msg.Answer {
		if qtype != dns.TypeANY && rr.Header().Rrtype != qtype {
			continue
		}
		answers = append(answers, extractRR(rr)...)
	}
	return answers
}

func ExtractAllAnswers(msg *dns.Msg) []string {
	var answers []string
	for _, rr := range msg.Answer {
		answers = append(answers, extractRR(rr)...)
	}
	return answers
}

func extractRR(rr dns.RR) []string {
	switch v := rr.(type) {
	case *dns.A:
		return []string{v.A.String()}
	case *dns.AAAA:
		return []string{v.AAAA.String()}
	case *dns.CNAME:
		return []string{v.Target}
	case *dns.NS:
		return []string{v.Ns}
	case *dns.MX:
		return []string{fmt.Sprintf("%d %s", v.Preference, v.Mx)}
	case *dns.TXT:
		return []string{strings.Join(v.Txt, " ")}
	case *dns.PTR:
		return []string{v.Ptr}
	case *dns.SOA:
		return []string{fmt.Sprintf("%s %s %d %d %d %d %d",
			v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)}
	case *dns.SRV:
		return []string{fmt.Sprintf("%d %d %d %s",
			v.Priority, v.Weight, v.Port, v.Target)}
	case *dns.CAA:
		return []string{fmt.Sprintf("%d %s %s", v.Flag, v.Tag, v.Value)}
	default:
		return []string{rr.String()}
	}
}
