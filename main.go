package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/flexdns/flexdns/pkg/runner"
)

func main() {
	opts := runner.DefaultOptions()

	var resolverStr string
	var recordTypeStr string
	var excludeTypeStr string
	var showVersion bool

	flag.StringVar(&opts.Domain, "d", "", "")
	flag.StringVar(&opts.Domain, "domain", "", "Target domain for subdomain bruteforce")
	flag.StringVar(&opts.Wordlist, "w", "", "")
	flag.StringVar(&opts.Wordlist, "wordlist", "", "Wordlist file for subdomain bruteforce")
	flag.StringVar(&resolverStr, "r", "", "")
	flag.StringVar(&resolverStr, "resolver", "", "Comma-separated list of resolvers")
	flag.StringVar(&opts.ResolverFile, "rL", "", "")
	flag.StringVar(&opts.ResolverFile, "resolver-file", "", "File containing list of resolvers")
	flag.StringVar(&recordTypeStr, "t", "A", "")
	flag.StringVar(&recordTypeStr, "type", "A", "DNS record types: A,AAAA,CNAME,NS,MX,TXT,PTR,SOA,SRV,CAA,ALL (comma-separated)")
	flag.StringVar(&excludeTypeStr, "et", "", "")
	flag.StringVar(&excludeTypeStr, "exclude-type", "", "Exclude record types (comma-separated, use with ALL)")
	flag.IntVar(&opts.Concurrency, "c", 10, "")
	flag.IntVar(&opts.Concurrency, "concurrency", 10, "Number of concurrent workers")
	flag.StringVar(&opts.Protocol, "protocol", "udp", "Protocol: udp, tcp, doh, dot")
	flag.BoolVar(&opts.JSONOutput, "json", false, "Output in JSON lines format")
	flag.BoolVar(&opts.JSONCompact, "json-compact", false, "Compact JSON output (short keys)")
	flag.BoolVar(&opts.Silent, "silent", false, "Silent mode (suppress banner and info)")
	flag.StringVar(&opts.OutputFile, "o", "", "")
	flag.StringVar(&opts.OutputFile, "output", "", "Output file path")
	flag.IntVar(&opts.Timeout, "timeout", 5, "DNS query timeout in seconds")
	flag.IntVar(&opts.Retries, "retry", 2, "Number of retries for failed queries")
	flag.BoolVar(&opts.WildcardFilter, "wf", true, "")
	flag.BoolVar(&opts.WildcardFilter, "wildcard-filter", true, "Enable wildcard detection and filtering")

	// Reconnaissance
	flag.BoolVar(&opts.AXFR, "axfr", false, "Attempt DNS zone transfer (AXFR)")
	flag.StringVar(&opts.AXFRDomain, "axfr-domain", "", "Domain for zone transfer (defaults to -d)")

	// Output enrichment
	flag.BoolVar(&opts.CDNDetect, "cdn", false, "Enable CDN provider detection")
	flag.BoolVar(&opts.ASNLookup, "asn", false, "Enable ASN lookup for IPs")

	// Performance & filtering
	flag.IntVar(&opts.RateLimit, "rate-limit", 0, "Queries per second limit (0=unlimited)")
	flag.StringVar(&opts.FilterRcode, "rcode", "", "Filter by response code (e.g., NOERROR, NXDOMAIN, SERVFAIL)")
	flag.BoolVar(&opts.ShowAnswer, "show-answer", true, "Show answer section")
	flag.BoolVar(&opts.ShowAuthority, "show-authority", false, "Show authority section in output")
	flag.BoolVar(&opts.ShowAdditional, "show-additional", false, "Show additional section in output")

	flag.BoolVar(&showVersion, "v", false, "")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Usage = printUsage
	flag.Parse()

	if showVersion {
		fmt.Println("flexdns v2.0.0")
		os.Exit(0)
	}

	runner.PrintBanner(opts.Silent)

	if resolverStr != "" {
		opts.Resolvers = strings.Split(resolverStr, ",")
	}

	opts.RecordTypes = strings.Split(strings.ToUpper(recordTypeStr), ",")

	if excludeTypeStr != "" {
		opts.ExcludeTypes = strings.Split(strings.ToUpper(excludeTypeStr), ",")
	}

	if opts.JSONCompact {
		opts.JSONOutput = true
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	r, err := runner.New(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] %s\n", err)
		os.Exit(1)
	}

	if err := r.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] %s\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	h := `flexdns - Fast DNS Resolution & Subdomain Enumeration Tool

USAGE:
  flexdns [flags]
  echo "example.com" | flexdns -t A
  flexdns -d example.com -w wordlist.txt -t A,AAAA

INPUT:
  -d,  -domain string         Target domain for subdomain bruteforce
  -w,  -wordlist string       Wordlist file for subdomain bruteforce
       (stdin)                 Pipe domains via stdin for batch resolution

RESOLVERS:
  -r,  -resolver string       Comma-separated resolvers (e.g., 8.8.8.8,1.1.1.1)
  -rL, -resolver-file string  File containing resolver list (one per line)
       -protocol string       Protocol: udp, tcp, doh, dot (default "udp")

QUERY:
  -t,  -type string           Record types: A,AAAA,CNAME,NS,MX,TXT,PTR,SOA,SRV,CAA,ALL
                              Use ALL to query all types at once (default "A")
  -et, -exclude-type string   Exclude specific types (comma-separated, use with ALL)
       -timeout int           Query timeout in seconds (default 5)
       -retry int             Retries for failed queries (default 2)

RECONNAISSANCE:
       -axfr                  Attempt DNS zone transfer (AXFR)
       -axfr-domain string    Domain for AXFR (defaults to -d value)

ENRICHMENT:
       -cdn                   Identify CDN provider from responses
       -asn                   Lookup ASN information for result IPs

FILTER:
  -wf, -wildcard-filter       Enable wildcard detection and filtering (default true)
       -rcode string          Filter results by DNS response code
                              (NOERROR, NXDOMAIN, SERVFAIL, REFUSED)

OUTPUT:
       -json                  Output results in JSON lines format
       -json-compact          Compact JSON with short keys (implies -json)
  -o,  -output string         Write results to file
       -silent                Suppress banner and informational messages
       -show-authority        Include authority section in output
       -show-additional       Include additional section in output

PERFORMANCE:
  -c,  -concurrency int       Number of concurrent workers (default 10)
       -rate-limit int        Max queries per second, 0=unlimited (default 0)

MISC:
  -v,  -version               Show version information
  -h,  -help                  Show this help message

EXAMPLES:
  # Resolve domains from stdin
  cat domains.txt | flexdns -t A -c 50

  # Query ALL record types, excluding PTR
  echo "example.com" | flexdns -t ALL -et PTR

  # Subdomain bruteforce with CDN detection
  flexdns -d example.com -w subdomains.txt -cdn -asn

  # Attempt zone transfer
  flexdns -d example.com -r ns1.example.com -axfr

  # Rate-limited scan with response code filter
  cat domains.txt | flexdns -t A -rate-limit 100 -rcode NOERROR

  # Compact JSON output with CDN identification
  echo "example.com" | flexdns -t A,AAAA,CNAME -json-compact -cdn

  # Show full DNS response sections
  echo "example.com" | flexdns -t A -show-authority -show-additional -json

  # Use DNS-over-HTTPS with silent mode
  echo "example.com" | flexdns -protocol doh -r dns.google -silent

  # DNS-over-TLS resolution
  echo "example.com" | flexdns -protocol dot -r 1.1.1.1

  # Bruteforce with wildcard filtering and file output
  flexdns -d example.com -w wordlist.txt -wf -o results.txt -json
`
	fmt.Fprint(os.Stderr, h)
}
