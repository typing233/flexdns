package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flexdns/flexdns/pkg/cdn"
	"github.com/flexdns/flexdns/pkg/output"
	"github.com/flexdns/flexdns/pkg/resolver"
	"github.com/flexdns/flexdns/pkg/retry"
	"github.com/flexdns/flexdns/pkg/wildcard"
	"github.com/miekg/dns"
)

type Runner struct {
	options   *Options
	resolvers []resolver.Resolver
	output    *output.Writer
	limiter   <-chan time.Time
}

func New(opts *Options) (*Runner, error) {
	addresses, err := loadResolvers(opts.Resolvers, opts.ResolverFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load resolvers: %w", err)
	}

	timeout := time.Duration(opts.Timeout) * time.Second
	var resolvers []resolver.Resolver
	for _, addr := range addresses {
		r, err := resolver.New(addr, opts.Protocol, timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to create resolver for %s: %w", addr, err)
		}
		resolvers = append(resolvers, r)
	}

	writer, err := output.NewWriter(output.WriterOptions{
		JSONMode:    opts.JSONOutput,
		CompactJSON: opts.JSONCompact,
		Silent:      opts.Silent,
		OutputPath:  opts.OutputFile,
		ShowAnswer:  opts.ShowAnswer,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create output writer: %w", err)
	}

	var limiter <-chan time.Time
	if opts.RateLimit > 0 {
		limiter = time.Tick(time.Second / time.Duration(opts.RateLimit))
	}

	return &Runner{
		options:   opts,
		resolvers: resolvers,
		output:    writer,
		limiter:   limiter,
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	defer r.output.Close()

	if r.options.AXFR {
		return r.runAXFR(ctx)
	}

	expandedTypes := resolver.ExpandRecordTypes(r.options.RecordTypes, r.options.ExcludeTypes)
	if len(expandedTypes) == 0 {
		return fmt.Errorf("no record types to query after applying exclusions")
	}
	r.options.RecordTypes = expandedTypes

	var inputCh <-chan string
	if r.options.Domain != "" && r.options.Wordlist != "" {
		ch, err := readFromWordlist(r.options.Wordlist, r.options.Domain)
		if err != nil {
			return fmt.Errorf("failed to read wordlist: %w", err)
		}
		inputCh = ch
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			inputCh = readFromStdin()
		} else {
			return fmt.Errorf("no input provided: use -d/-w for bruteforce or pipe domains via stdin")
		}
	}

	var wdetector *wildcard.Detector
	if r.options.WildcardFilter && r.options.Domain != "" {
		wdetector = wildcard.NewDetector(r.resolvers[0], r.options.Domain)
		if err := wdetector.Detect(ctx); err == nil && wdetector.HasWildcard {
			if !r.options.Silent {
				fmt.Fprintf(os.Stderr, "[WRN] Wildcard detected for %s: %s\n",
					r.options.Domain, strings.Join(wdetector.WildcardIPs(), ", "))
			}
		}
	}

	var counter uint64
	var wg sync.WaitGroup

	for i := 0; i < r.options.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range inputCh {
				if ctx.Err() != nil {
					return
				}
				idx := atomic.AddUint64(&counter, 1)
				res := r.resolvers[int(idx)%len(r.resolvers)]

				for _, rt := range r.options.RecordTypes {
					qtype, ok := resolver.ParseType(rt)
					if !ok {
						continue
					}
					if r.limiter != nil {
						<-r.limiter
					}
					r.resolveWithRetry(ctx, res, domain, rt, qtype, wdetector)
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

func (r *Runner) runAXFR(ctx context.Context) error {
	domain := r.options.AXFRDomain
	if domain == "" {
		domain = r.options.Domain
	}
	if domain == "" {
		return fmt.Errorf("AXFR requires a target domain (-d or -axfr-domain)")
	}

	if len(r.resolvers) == 0 {
		return fmt.Errorf("AXFR requires at least one resolver (nameserver)")
	}

	timeout := time.Duration(r.options.Timeout) * time.Second
	server := r.resolvers[0].Address()

	if !r.options.Silent {
		fmt.Fprintf(os.Stderr, "[INF] Attempting zone transfer for %s from %s\n", domain, server)
	}

	result, err := resolver.PerformAXFR(ctx, server, domain, timeout)
	if err != nil {
		return fmt.Errorf("AXFR failed: %w", err)
	}

	if !r.options.Silent {
		fmt.Fprintf(os.Stderr, "[INF] Zone transfer successful: %d records\n", len(result.Records))
	}

	if r.options.JSONOutput {
		for _, rec := range result.Records {
			data, _ := json.Marshal(rec)
			r.output.WriteRaw(string(data))
		}
	} else {
		for _, rec := range result.Records {
			line := fmt.Sprintf("%s\t%d\t%s\t%s", rec.Name, rec.TTL, rec.Type, rec.Value)
			r.output.WriteRaw(line)
		}
	}

	return nil
}

func (r *Runner) resolveWithRetry(ctx context.Context, res resolver.Resolver, domain string, typeName string, qtype uint16, wd *wildcard.Detector) {
	var result *resolver.Result

	retryCfg := retry.DefaultConfig(r.options.Retries)
	err := retry.Do(ctx, retryCfg, func() error {
		var resolveErr error
		result, resolveErr = res.Resolve(ctx, domain, qtype)
		return resolveErr
	})

	if err != nil || result == nil || result.Raw == nil {
		return
	}

	if r.options.FilterRcode != "" {
		rcode := dns.RcodeToString[result.Raw.Rcode]
		if !strings.EqualFold(rcode, r.options.FilterRcode) {
			return
		}
	}

	answers := result.Answers
	if len(answers) == 0 && r.options.FilterRcode == "" {
		return
	}

	if wd != nil && wd.IsWildcard(answers) {
		return
	}

	record := &output.Record{
		Domain:   domain,
		Type:     typeName,
		Resolver: res.Address(),
		Protocol: res.Protocol(),
		Answers:  answers,
		Rcode:    dns.RcodeToString[result.Raw.Rcode],
	}

	if r.options.ShowAuthority && result.Raw != nil {
		for _, rr := range result.Raw.Ns {
			record.Authority = append(record.Authority, rr.String())
		}
	}
	if r.options.ShowAdditional && result.Raw != nil {
		for _, rr := range result.Raw.Extra {
			record.Additional = append(record.Additional, rr.String())
		}
	}

	if r.options.CDNDetect {
		if info := cdn.Identify(answers); info != nil {
			record.CDN = &output.CDNInfo{Provider: info.Provider, Matched: info.Matched}
		}
	}

	if r.options.ASNLookup {
		for _, ans := range answers {
			if info := cdn.LookupASN(ctx, ans, 3*time.Second); info != nil {
				record.ASN = &output.ASNInfo{ASN: info.ASN, Desc: info.Desc}
				break
			}
		}
	}

	r.output.Write(record)
}
