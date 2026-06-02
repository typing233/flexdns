package cdn

import (
	"net"
	"strings"
)

type CDNInfo struct {
	Provider string `json:"provider"`
	Matched  string `json:"matched"`
}

type cdnCIDR struct {
	network  *net.IPNet
	provider string
}

var cnameSignatures = map[string]string{
	".cloudfront.net":       "Amazon CloudFront",
	".cloudflare.net":       "Cloudflare",
	".akamaiedge.net":      "Akamai",
	".akamai.net":          "Akamai",
	".akamaitechnologies":  "Akamai",
	".edgekey.net":         "Akamai",
	".edgesuite.net":       "Akamai",
	".fastly.net":          "Fastly",
	".fastlylb.net":        "Fastly",
	".azureedge.net":       "Azure CDN",
	".azurefd.net":         "Azure Front Door",
	".msecnd.net":          "Azure CDN",
	".googleusercontent.com": "Google Cloud CDN",
	".googleapis.com":      "Google Cloud",
	".gstatic.com":         "Google",
	".cdn.cloudflare.net":  "Cloudflare",
	".hwcdn.net":           "Highwinds/StackPath",
	".stackpathdns.com":    "StackPath",
	".netdna-cdn.com":      "StackPath",
	".kxcdn.com":           "KeyCDN",
	".cdn77.org":           "CDN77",
	".incapdns.net":        "Imperva/Incapsula",
	".impervadns.net":      "Imperva",
	".sucuri.net":          "Sucuri",
	".cdn.jsdelivr.net":    "jsDelivr",
	".netlify.app":         "Netlify",
	".vercel-dns.com":      "Vercel",
	".livecdn.net":         "Tencent Cloud CDN",
	".cdnhwc1.com":         "Huawei CDN",
	".kunlunaq.com":        "Alibaba Cloud CDN",
	".alikunlun.com":       "Alibaba Cloud CDN",
	".cdngslb.com":         "Alibaba Cloud CDN",
	".tbcache.com":         "Alibaba Cloud CDN",
	".tcdn.qq.com":         "Tencent Cloud CDN",
	".cdn.dnsv1.com":       "Tencent Cloud CDN",
	".baiducontent.com":    "Baidu CDN",
	".bdydns.com":          "Baidu CDN",
	".wsdvs.com":           "ChinaNetCenter/Wangsu",
	".wscdns.com":          "ChinaNetCenter/Wangsu",
	".ourwebpic.com":       "ChinaNetCenter/Wangsu",
	".lxdns.com":           "ChinaNetCenter/Wangsu",
	".cdn20.com":           "ChinaCache",
	".chinacache.net":      "ChinaCache",
}

var cdnCIDRs []cdnCIDR

func init() {
	cidrs := map[string][]string{
		"Cloudflare": {
			"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
			"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
			"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
			"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		},
		"Amazon CloudFront": {
			"130.176.0.0/18", "205.251.192.0/19", "204.246.164.0/22",
			"204.246.168.0/22", "13.32.0.0/15", "13.224.0.0/14",
			"52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16",
			"54.230.0.0/17", "54.239.128.0/18", "54.239.192.0/19",
			"99.84.0.0/16", "143.204.0.0/16", "18.64.0.0/14",
		},
		"Fastly": {
			"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
			"103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
			"140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17",
			"151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
			"167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
			"172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
			"199.232.0.0/16",
		},
		"Akamai": {
			"23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14",
			"23.72.0.0/13", "104.64.0.0/10",
		},
	}

	for provider, nets := range cidrs {
		for _, cidr := range nets {
			_, network, err := net.ParseCIDR(cidr)
			if err == nil {
				cdnCIDRs = append(cdnCIDRs, cdnCIDR{network: network, provider: provider})
			}
		}
	}
}

func Identify(answers []string) *CDNInfo {
	for _, answer := range answers {
		lower := strings.ToLower(answer)
		for sig, provider := range cnameSignatures {
			if strings.Contains(lower, sig) {
				return &CDNInfo{Provider: provider, Matched: "cname:" + sig}
			}
		}
	}

	for _, answer := range answers {
		ip := net.ParseIP(answer)
		if ip == nil {
			continue
		}
		for _, entry := range cdnCIDRs {
			if entry.network.Contains(ip) {
				return &CDNInfo{Provider: entry.provider, Matched: "ip:" + entry.network.String()}
			}
		}
	}

	return nil
}
