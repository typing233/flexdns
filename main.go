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
	flag.StringVar(&recordTypeStr, "type", "A", "DNS record types: A,AAAA,CNAME,NS,MX,TXT,PTR,SOA,SRV (comma-separated)")
	flag.IntVar(&opts.Concurrency, "c", 10, "")
	flag.IntVar(&opts.Concurrency, "concurrency", 10, "Number of concurrent workers")
	flag.StringVar(&opts.Protocol, "protocol", "udp", "Protocol: udp, tcp, doh, dot")
	flag.BoolVar(&opts.JSONOutput, "json", false, "Output in JSON lines format")
	flag.BoolVar(&opts.Silent, "silent", false, "Silent mode (suppress banner and info)")
	flag.StringVar(&opts.OutputFile, "o", "", "")
	flag.StringVar(&opts.OutputFile, "output", "", "Output file path")
	flag.IntVar(&opts.Timeout, "timeout", 5, "DNS query timeout in seconds")
	flag.IntVar(&opts.Retries, "retry", 2, "Number of retries for failed queries")
	flag.BoolVar(&opts.WildcardFilter, "wf", true, "")
	flag.BoolVar(&opts.WildcardFilter, "wildcard-filter", true, "Enable wildcard detection and filtering")
	flag.BoolVar(&showVersion, "v", false, "")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Usage = printUsage
	flag.Parse()

	if showVersion {
		fmt.Println("flexdns v1.0.0")
		os.Exit(0)
	}

	runner.PrintBanner(opts.Silent)

	if resolverStr != "" {
		opts.Resolvers = strings.Split(resolverStr, ",")
	}

	opts.RecordTypes = strings.Split(strings.ToUpper(recordTypeStr), ",")

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
  -t,  -type string           Record types: A,AAAA,CNAME,NS,MX,TXT,PTR,SOA,SRV
                              Comma-separated for multiple (default "A")
       -timeout int           Query timeout in seconds (default 5)
       -retry int             Retries for failed queries (default 2)

FILTER:
  -wf, -wildcard-filter       Enable wildcard detection and filtering (default true)

OUTPUT:
       -json                  Output results in JSON lines format
  -o,  -output string         Write results to file
       -silent                Suppress banner and informational messages

MISC:
  -c,  -concurrency int       Number of concurrent workers (default 10)
  -v,  -version               Show version information
  -h,  -help                  Show this help message

EXAMPLES:
  # Resolve domains from stdin
  cat domains.txt | flexdns -t A -c 50

  # Subdomain bruteforce with custom resolvers
  flexdns -d example.com -w subdomains.txt -r 8.8.8.8,1.1.1.1 -c 100

  # Query multiple record types with JSON output
  echo "example.com" | flexdns -t A,AAAA,MX -json

  # Use DNS-over-HTTPS with silent mode
  echo "example.com" | flexdns -protocol doh -r dns.google -silent

  # DNS-over-TLS resolution
  echo "example.com" | flexdns -protocol dot -r 1.1.1.1

  # Bruteforce with wildcard filtering and file output
  flexdns -d example.com -w wordlist.txt -wf -o results.txt -json
`
	fmt.Fprint(os.Stderr, h)
}
