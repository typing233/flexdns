package resolver

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

type DoHResolver struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

func NewDoH(address string, timeout time.Duration) *DoHResolver {
	url := normalizeDoHURL(address)
	return &DoHResolver{
		url: url,
		client: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

func (r *DoHResolver) Resolve(ctx context.Context, domain string, qtype uint16) (*Result, error) {
	msg := buildQuery(domain, qtype)
	wireMsg, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(wireMsg)
	reqURL := fmt.Sprintf("%s?dns=%s", r.url, encoded)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return &Result{Answers: ExtractAnswers(dnsResp, qtype), Raw: dnsResp}, nil
}

func (r *DoHResolver) Protocol() string { return "doh" }
func (r *DoHResolver) Address() string  { return r.url }

