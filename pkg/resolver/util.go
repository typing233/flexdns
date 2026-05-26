package resolver

import (
	"net"
	"strings"
)

func normalizeAddress(address string, defaultPort string) string {
	if strings.Contains(address, "://") {
		return address
	}
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return net.JoinHostPort(address, defaultPort)
	}
	return address
}

func normalizeDoHURL(address string) string {
	if strings.HasPrefix(address, "https://") {
		if !strings.Contains(address[8:], "/") {
			return address + "/dns-query"
		}
		return address
	}
	if strings.HasPrefix(address, "http://") {
		if !strings.Contains(address[7:], "/") {
			return address + "/dns-query"
		}
		return address
	}
	return "https://" + address + "/dns-query"
}

func splitHostPort(address string) (string, string) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address, ""
	}
	return host, port
}
