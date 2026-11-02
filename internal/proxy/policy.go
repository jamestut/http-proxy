package proxy

import (
	"fmt"
	"net/netip"
	"strings"
)

type ipRule struct {
	prefix netip.Prefix
	route  *string
}

type domainRule struct {
	suffix   string
	wildcard bool
	route    *string
}

type policy struct {
	defaults rawDefaults
	ips      []ipRule
	domains  []domainRule
}

func compilePolicy(raw rawConfig, upstreams map[string]*Upstream) (policy, error) {
	p := policy{defaults: raw.Defaults}
	check := func(route *string) error {
		if route == nil {
			return nil
		}
		if _, ok := upstreams[*route]; !ok {
			return fmt.Errorf("unknown upstream %q", *route)
		}
		return nil
	}
	for _, route := range []*string{raw.Defaults.IP, raw.Defaults.Domain, raw.Defaults.UnqualifiedDomain} {
		if err := check(route); err != nil {
			return policy{}, fmt.Errorf("defaults: %w", err)
		}
	}
	prefixes := make(map[netip.Prefix]*string)
	for input, route := range raw.IP {
		if err := check(route); err != nil {
			return policy{}, fmt.Errorf("IP rule %q: %w", input, err)
		}
		prefix, err := netip.ParsePrefix(input)
		if err != nil {
			return policy{}, fmt.Errorf("invalid IP rule %q: %w", input, err)
		}
		prefix = prefix.Masked()
		if old, ok := prefixes[prefix]; ok {
			if !sameRoute(old, route) {
				return policy{}, fmt.Errorf("conflicting IP rules for %s", prefix)
			}
			continue
		}
		prefixes[prefix] = route
		p.ips = append(p.ips, ipRule{prefix, route})
	}
	patterns := make(map[string]*string)
	for input, route := range raw.Domain {
		if err := check(route); err != nil {
			return policy{}, fmt.Errorf("domain rule %q: %w", input, err)
		}
		pattern := canonicalDomain(input)
		wildcard := strings.HasPrefix(pattern, "*.")
		suffix := pattern
		if wildcard {
			suffix = strings.TrimPrefix(pattern, "*.")
		}
		if err := validateDomain(suffix); err != nil {
			return policy{}, fmt.Errorf("invalid domain rule %q: %w", input, err)
		}
		if old, ok := patterns[pattern]; ok {
			if !sameRoute(old, route) {
				return policy{}, fmt.Errorf("conflicting domain rules for %s", pattern)
			}
			continue
		}
		patterns[pattern] = route
		p.domains = append(p.domains, domainRule{suffix, wildcard, route})
	}
	return p, nil
}

func sameRoute(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func (cfg *Config) RouteIP(addr netip.Addr) *string {
	addr = addr.Unmap()
	best := -1
	route := cfg.policy.defaults.IP
	for _, rule := range cfg.policy.ips {
		if rule.prefix.Bits() > best && rule.prefix.Contains(addr) {
			best = rule.prefix.Bits()
			route = rule.route
		}
	}
	return route
}

func (cfg *Config) RouteDomain(host string) *string {
	host = canonicalDomain(host)
	route := cfg.policy.defaults.Domain
	if !strings.Contains(host, ".") {
		route = cfg.policy.defaults.UnqualifiedDomain
	}
	best := -1
	for _, rule := range cfg.policy.domains {
		if !rule.wildcard && host == rule.suffix {
			return rule.route
		}
		if rule.wildcard && strings.HasSuffix(host, "."+rule.suffix) && len(rule.suffix) > best {
			best = len(rule.suffix)
			route = rule.route
		}
	}
	return route
}

func canonicalDomain(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func validateDomain(name string) error {
	if name == "" || len(name) > 253 {
		return fmt.Errorf("empty or too long")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid label %q", label)
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return fmt.Errorf("invalid character in label %q", label)
			}
		}
	}
	return nil
}
