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
}

func ParseType(s string) (uint16, bool) {
	t, ok := TypeMap[strings.ToUpper(s)]
	return t, ok
}

func ExtractAnswers(msg *dns.Msg) []string {
	var answers []string
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			answers = append(answers, v.A.String())
		case *dns.AAAA:
			answers = append(answers, v.AAAA.String())
		case *dns.CNAME:
			answers = append(answers, v.Target)
		case *dns.NS:
			answers = append(answers, v.Ns)
		case *dns.MX:
			answers = append(answers, fmt.Sprintf("%d %s", v.Preference, v.Mx))
		case *dns.TXT:
			answers = append(answers, strings.Join(v.Txt, " "))
		case *dns.PTR:
			answers = append(answers, v.Ptr)
		case *dns.SOA:
			answers = append(answers, fmt.Sprintf("%s %s %d %d %d %d %d",
				v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl))
		case *dns.SRV:
			answers = append(answers, fmt.Sprintf("%d %d %d %s",
				v.Priority, v.Weight, v.Port, v.Target))
		}
	}
	return answers
}
