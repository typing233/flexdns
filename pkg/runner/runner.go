package runner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flexdns/flexdns/pkg/output"
	"github.com/flexdns/flexdns/pkg/resolver"
	"github.com/flexdns/flexdns/pkg/wildcard"
)

type Runner struct {
	options   *Options
	resolvers []resolver.Resolver
	output    *output.Writer
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

	writer, err := output.NewWriter(opts.JSONOutput, opts.Silent, opts.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output writer: %w", err)
	}

	return &Runner{
		options:   opts,
		resolvers: resolvers,
		output:    writer,
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	defer r.output.Close()

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
					r.resolveWithRetry(ctx, res, domain, rt, qtype, wdetector)
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

func (r *Runner) resolveWithRetry(ctx context.Context, res resolver.Resolver, domain string, typeName string, qtype uint16, wd *wildcard.Detector) {
	var result *resolver.Result
	var err error

	for attempt := 0; attempt <= r.options.Retries; attempt++ {
		result, err = res.Resolve(ctx, domain, qtype)
		if err == nil {
			break
		}
		if attempt < r.options.Retries {
			time.Sleep(time.Duration(100*(1<<attempt)) * time.Millisecond)
		}
	}

	if err != nil || result == nil || len(result.Answers) == 0 {
		return
	}

	if wd != nil && wd.IsWildcard(result.Answers) {
		return
	}

	r.output.Write(&output.Record{
		Domain:   domain,
		Type:     typeName,
		Resolver: res.Address(),
		Protocol: res.Protocol(),
		Answers:  result.Answers,
	})
}
