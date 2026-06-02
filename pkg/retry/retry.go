package retry

import (
	"context"
	"math/rand"
	"net"
	"strings"
	"time"
)

type Config struct {
	MaxRetries  int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
	JitterRatio float64
}

func DefaultConfig(maxRetries int) *Config {
	return &Config{
		MaxRetries:  maxRetries,
		BaseDelay:   200 * time.Millisecond,
		MaxDelay:    10 * time.Second,
		JitterRatio: 0.3,
	}
}

func Do(ctx context.Context, cfg *Config, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if !isRetryable(lastErr) {
			return lastErr
		}
		if attempt < cfg.MaxRetries {
			delay := backoffWithJitter(attempt, cfg)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	return lastErr
}

func backoffWithJitter(attempt int, cfg *Config) time.Duration {
	delay := cfg.BaseDelay * (1 << attempt)
	if delay > cfg.MaxDelay {
		delay = cfg.MaxDelay
	}
	jitter := time.Duration(float64(delay) * cfg.JitterRatio * (rand.Float64()*2 - 1))
	delay += jitter
	if delay < 0 {
		delay = cfg.BaseDelay
	}
	return delay
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}

	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}

	msg := err.Error()
	retryableMessages := []string{
		"i/o timeout",
		"connection refused",
		"connection reset",
		"no such host",
		"server misbehaving",
		"network is unreachable",
		"no route to host",
		"temporary failure",
		"EOF",
		"broken pipe",
	}
	for _, rm := range retryableMessages {
		if strings.Contains(msg, rm) {
			return true
		}
	}
	return false
}
