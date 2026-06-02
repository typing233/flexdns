package runner

type Options struct {
	Domain         string
	Wordlist       string
	Resolvers      []string
	ResolverFile   string
	RecordTypes    []string
	ExcludeTypes   []string
	Concurrency    int
	Protocol       string
	JSONOutput     bool
	JSONCompact    bool
	Silent         bool
	OutputFile     string
	Timeout        int
	Retries        int
	WildcardFilter bool

	// Reconnaissance
	AXFR       bool
	AXFRDomain string

	// Output enrichment
	CDNDetect bool
	ASNLookup bool

	// Performance & filtering
	RateLimit    int
	FilterRcode  string
	ShowAnswer   bool
	ShowAuthority bool
	ShowAdditional bool
}

func DefaultOptions() *Options {
	return &Options{
		RecordTypes:    []string{"A"},
		Concurrency:    10,
		Protocol:       "udp",
		Timeout:        5,
		Retries:        2,
		WildcardFilter: true,
		ShowAnswer:     true,
		ShowAuthority:  false,
		ShowAdditional: false,
	}
}
