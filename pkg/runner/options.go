package runner

type Options struct {
	Domain         string
	Wordlist       string
	Resolvers      []string
	ResolverFile   string
	RecordTypes    []string
	Concurrency    int
	Protocol       string
	JSONOutput     bool
	Silent         bool
	OutputFile     string
	Timeout        int
	Retries        int
	WildcardFilter bool
}

func DefaultOptions() *Options {
	return &Options{
		RecordTypes:    []string{"A"},
		Concurrency:    10,
		Protocol:       "udp",
		Timeout:        5,
		Retries:        2,
		WildcardFilter: true,
	}
}
