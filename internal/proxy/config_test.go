package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadTestConfig(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

func TestRoutingDecisions(t *testing.T) {
	cfg, err := loadTestConfig(t, `{
		"upstreams":{"a":{"host":"http://proxy"},"b":{"host":"https://proxy"}},
		"defaults":{"ip":"a","domain":"b","unqualified-domain":"a"},
		"ip":{"10.0.0.0/8":null,"10.4.0.0/16":"b","2001:db8::/32":"b","2001:db8:1::/48":null},
		"domain":{"*.example.com":"a","*.nested.example.com":null,"site.nested.example.com":"b","local":null}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ addr, want string }{
		{"8.8.8.8", "a"}, {"10.1.2.3", ""}, {"10.4.2.3", "b"},
		{"::ffff:10.4.2.3", "b"}, {"2001:db8:2::1", "b"}, {"2001:db8:1::1", ""},
	} {
		t.Run(tc.addr, func(t *testing.T) { checkRoute(t, cfg.RouteIP(netip.MustParseAddr(tc.addr)), tc.want) })
	}
	for _, tc := range []struct{ host, want string }{
		{"example.com", "b"}, {"one.example.com", "a"}, {"deep.one.EXAMPLE.com.", "a"},
		{"a.nested.example.com", ""}, {"site.nested.example.com", "b"},
		{"nested.example.com", "a"}, {"local", ""}, {"printer", "a"},
	} {
		t.Run(tc.host, func(t *testing.T) { checkRoute(t, cfg.RouteDomain(tc.host), tc.want) })
	}
}

func checkRoute(t *testing.T, actual *string, want string) {
	t.Helper()
	if want == "" {
		if actual != nil {
			t.Fatalf("got route %q, want nil", *actual)
		}
	} else if actual == nil || *actual != want {
		t.Fatalf("got route %v, want %q", actual, want)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unknown field", `{"mystery":1}`},
		{"null config", `null`},
		{"trailing object", `{} {}`},
		{"invalid JSON", `{"auth":{},}`},
		{"unpaired high surrogate", `{"auth":{"type":"basic","credentials":[{"username":"a","password":"\ud800"}]}}`},
		{"unpaired low surrogate", `{"auth":{"type":"basic","credentials":[{"username":"a","password":"\udc00"}]}}`},
		{"missing auth type", `{"auth":{"credentials":[{"username":"a","password":"b"}]}}`},
		{"empty credential list", `{"auth":{"type":"basic","credentials":[]}}`},
		{"bad username", `{"auth":{"type":"basic","credentials":[{"username":"A","password":"b"}]}}`},
		{"colon in username", `{"auth":{"type":"basic","credentials":[{"username":"a:b","password":"b"}]}}`},
		{"empty password", `{"auth":{"type":"basic","credentials":[{"username":"a","password":""}]}}`},
		{"control password", `{"auth":{"type":"basic","credentials":[{"username":"a","password":"bad\npassword"}]}}`},
		{"bad upstream auth", `{"upstreams":{"a":{"host":"http://proxy","auth":{"type":"apikey","username":"a","password":"b"}}}}`},
		{"missing upstream", `{"defaults":{"ip":"missing"}}`},
		{"missing rule upstream", `{"domain":{"example.com":"missing"}}`},
		{"invalid prefix", `{"ip":{"10.0.0.0/33":null}}`},
		{"conflicting prefixes", `{"upstreams":{"a":{"host":"http://proxy"}},"ip":{"10.1.0.0/8":"a","10.0.0.0/8":null}}`},
		{"bad domain wildcard", `{"domain":{"a*.example.com":null}}`},
		{"conflicting domain names", `{"upstreams":{"a":{"host":"http://proxy"}},"domain":{"EXAMPLE.COM":"a","example.com.":null}}`},
		{"invalid scheme", `{"upstreams":{"a":{"host":"socks5://proxy"}}}`},
		{"credentials in URL", `{"upstreams":{"a":{"host":"http://user:pass@proxy"}}}`},
		{"upstream path", `{"upstreams":{"a":{"host":"http://proxy/path"}}}`},
		{"bad upstream port", `{"upstreams":{"a":{"host":"http://proxy:65536"}}}`},
		{"unbracketed IPv6", `{"upstreams":{"a":{"host":"http://::1:80"}}}`},
		{"multiple ports", `{"upstreams":{"a":{"host":"http://proxy:80:90"}}}`},
		{"unpaired cert", `{"tls":{"cert":"cert.pem"}}`},
		{"missing CA", `{"tls":{"upstream_ca":"missing.pem"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadTestConfig(t, tc.body); err == nil {
				t.Fatal("expected invalid config")
			}
		})
	}
	cfg, err := loadTestConfig(t, `{"auth":{"type":"basic","credentials":[{"username":"hello123","password":"你好:world"}]}}`)
	if err != nil || cfg.Auth.Credentials[0].Password != "你好:world" {
		t.Fatalf("UTF-8 password with colon: cfg=%v, err=%v", cfg, err)
	}
	cfg, err = loadTestConfig(t, `{"auth":{"type":"basic","credentials":[{"username":"a","password":"\ud83d\ude00"}]}}`)
	if err != nil || cfg.Auth.Credentials[0].Password != "😀" {
		t.Fatalf("valid surrogate pair: cfg=%v, err=%v", cfg, err)
	}
}

func TestTLSFilesRelativeToConfig(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for name, data := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"tls":{"cert":"cert.pem","key":"key.pem","upstream_ca":"cert.pem"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddCACertificates(x509.NewCertPool(), append(certPEM, []byte("junk")...)); err == nil {
		t.Fatal("invalid trailing CA content accepted")
	}
	if cfg.Certificate == nil || cfg.Roots == nil {
		t.Fatal("expected certificate and CA pool")
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadConfig(path)
	if err == nil || !strings.Contains(fmt.Sprint(err), "TLS") {
		t.Fatalf("expected TLS file error, got %v", err)
	}
}
