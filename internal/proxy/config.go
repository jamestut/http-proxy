package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Config is a validated snapshot shared by requests until the next reload.
type Config struct {
	Auth        *AuthConfig
	Upstreams   map[string]*Upstream
	Certificate *tls.Certificate
	Roots       *x509.CertPool
	policy      policy
}

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AuthConfig struct {
	Type        string       `json:"type"`
	Credentials []Credential `json:"credentials"`
}

type Upstream struct {
	URL  *url.URL
	Auth *Credential
}

type rawUpstreamAuth struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type rawUpstream struct {
	Host json.RawMessage  `json:"host"`
	Auth *rawUpstreamAuth `json:"auth"`
}

type rawTLS struct {
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	UpstreamCA string `json:"upstream_ca"`
}

type rawDefaults struct {
	IP                *string `json:"ip"`
	Domain            *string `json:"domain"`
	UnqualifiedDomain *string `json:"unqualified-domain"`
}

type rawConfig struct {
	TLS       *rawTLS                 `json:"tls"`
	Auth      *AuthConfig             `json:"auth"`
	Upstreams map[string]*rawUpstream `json:"upstreams"`
	Defaults  rawDefaults             `json:"defaults"`
	IP        map[string]*string      `json:"ip"`
	Domain    map[string]*string      `json:"domain"`
}

func LoadConfig(path string) (*Config, error) {
	return loadConfig(path, false)
}

func LoadReverseConfig(path string) (*Config, error) {
	return loadConfig(path, true)
}

func loadConfig(path string, reverse bool) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return parseConfig(data, path, reverse)
}

func ParseConfig(data []byte, path string) (*Config, error) {
	return parseConfig(data, path, false)
}

func ParseReverseConfig(data []byte, path string) (*Config, error) {
	return parseConfig(data, path, true)
}

func parseConfig(data []byte, path string, reverse bool) (*Config, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("config is not valid UTF-8")
	}
	if err := validateJSONSurrogates(data); err != nil {
		return nil, err
	}
	var raw rawConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("config must contain exactly one JSON object")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, fmt.Errorf("config must be a JSON object")
	}

	cfg := &Config{Auth: raw.Auth, Upstreams: make(map[string]*Upstream)}
	if raw.Auth != nil {
		if raw.Auth.Type != "basic" {
			return nil, fmt.Errorf("auth type must be basic")
		}
		if len(raw.Auth.Credentials) == 0 {
			return nil, fmt.Errorf("auth credentials must not be empty")
		}
		for i, cred := range raw.Auth.Credentials {
			if err := validateCredential(cred); err != nil {
				return nil, fmt.Errorf("auth credential %d: %w", i+1, err)
			}
		}
	}
	credentials := make(map[Credential]bool)
	for name, up := range raw.Upstreams {
		if strings.TrimSpace(name) != name || name == "" {
			return nil, fmt.Errorf("invalid upstream name %q", name)
		}
		if up == nil {
			return nil, fmt.Errorf("upstream %q must be an object", name)
		}
		compiled := &Upstream{}
		if reverse {
			if up.Host != nil {
				return nil, fmt.Errorf("upstream %q must not have a host", name)
			}
			if up.Auth == nil {
				return nil, fmt.Errorf("upstream %q requires authentication", name)
			}
		} else {
			var host string
			if up.Host != nil {
				if err := json.Unmarshal(up.Host, &host); err != nil {
					return nil, fmt.Errorf("upstream %q: invalid host", name)
				}
			}
			u, err := parseUpstreamURL(host)
			if err != nil {
				return nil, fmt.Errorf("upstream %q: %w", name, err)
			}
			compiled.URL = u
		}
		if up.Auth != nil {
			if up.Auth.Type != "basic" {
				return nil, fmt.Errorf("upstream %q auth type must be basic", name)
			}
			cred := Credential{Username: up.Auth.Username, Password: up.Auth.Password}
			if err := validateCredential(cred); err != nil {
				return nil, fmt.Errorf("upstream %q credentials: %w", name, err)
			}
			if reverse && credentials[cred] {
				return nil, fmt.Errorf("duplicate upstream credentials")
			}
			credentials[cred] = true
			compiled.Auth = &cred
		}
		cfg.Upstreams[name] = compiled
	}
	if raw.TLS != nil {
		if (raw.TLS.Cert == "") != (raw.TLS.Key == "") {
			return nil, fmt.Errorf("tls cert and key must be configured together")
		}
		if raw.TLS.Cert != "" {
			cert, err := tls.LoadX509KeyPair(configPath(path, raw.TLS.Cert), configPath(path, raw.TLS.Key))
			if err != nil {
				return nil, fmt.Errorf("load TLS certificate and key: %w", err)
			}
			cfg.Certificate = &cert
		}
		if raw.TLS.UpstreamCA != "" {
			pem, err := os.ReadFile(configPath(path, raw.TLS.UpstreamCA))
			if err != nil {
				return nil, fmt.Errorf("read upstream CA: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("load system CA pool: %w", err)
			}
			if err := addCACertificates(pool, pem); err != nil {
				return nil, fmt.Errorf("invalid upstream CA file: %w", err)
			}
			cfg.Roots = pool
		}
	}
	p, err := compilePolicy(raw, cfg.Upstreams)
	if err != nil {
		return nil, err
	}
	cfg.policy = p
	return cfg, nil
}

func configPath(config, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(filepath.Dir(config), path)
}

func validateCredential(cred Credential) error {
	if cred.Username == "" {
		return fmt.Errorf("username must not be empty")
	}
	for _, c := range cred.Username {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("username must contain only lowercase ASCII letters and digits")
		}
	}
	if cred.Password == "" || !utf8.ValidString(cred.Password) {
		return fmt.Errorf("password must be nonempty UTF-8")
	}
	for _, c := range cred.Password {
		if unicode.IsControl(c) {
			return fmt.Errorf("password must not contain control characters")
		}
	}
	return nil
}

func parseUpstreamURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid host URL")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("host must be an HTTP or HTTPS proxy URL without credentials, path, query, or fragment")
	}
	if strings.Contains(u.Hostname(), ":") {
		if !strings.HasPrefix(u.Host, "[") {
			return nil, fmt.Errorf("IPv6 upstream addresses must be bracketed")
		}
		if _, err := netip.ParseAddr(u.Hostname()); err != nil {
			return nil, fmt.Errorf("invalid IPv6 upstream address")
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("upstream port must not be empty")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid upstream port")
		}
	}
	return u, nil
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject them so
// configured credentials are never silently changed while decoding JSON.
func validateJSONSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		if !inString {
			if data[i] == '"' {
				inString = true
			}
			continue
		}
		if data[i] == '"' {
			inString = false
			continue
		}
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			break
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			break
		}
		v, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			continue
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return fmt.Errorf("config contains an unpaired Unicode surrogate")
		}
		if v < 0xd800 || v > 0xdbff {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return fmt.Errorf("config contains an unpaired Unicode surrogate")
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return fmt.Errorf("config contains an unpaired Unicode surrogate")
		}
		i += 6
	}
	return nil
}

func addCACertificates(pool *x509.CertPool, data []byte) error {
	count := 0
	for {
		data = bytes.TrimSpace(data)
		if len(data) == 0 {
			break
		}
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return fmt.Errorf("expected PEM certificate")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid PEM certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("invalid certificate: %w", err)
		}
		pool.AddCert(cert)
		count++
		data = rest
	}
	if count == 0 {
		return fmt.Errorf("no certificates")
	}
	return nil
}
