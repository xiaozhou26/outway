package masque

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/xiaozhou26/outway/internal/config"
	"github.com/xiaozhou26/outway/internal/ext"
)

func TestTemplateURL(t *testing.T) {
	got := templateURL(netip.MustParseAddrPort("[2001:db8::1]:443"))
	want := "https://[2001:db8::1]:443/.well-known/masque/udp/{target_host}/{target_port}/"
	if got != want {
		t.Fatalf("templateURL() = %q, want %q", got, want)
	}
}

func TestAuthenticateProxyAuthorizationAndExtension(t *testing.T) {
	auth := config.AuthMode{Username: "user", Password: "secret"}
	request, err := http.NewRequest(http.MethodConnect, "https://proxy.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("user-session-sticky:secret"))
	request.Header.Set("Proxy-Authorization", "Basic "+credentials)

	extension, ok := authenticate(request, auth)
	if !ok {
		t.Fatal("valid proxy credentials were rejected")
	}
	if extension.Type != ext.ExtSession {
		t.Fatalf("extension type = %v, want session", extension.Type)
	}
}

func TestAuthenticateRejectsWrongPassword(t *testing.T) {
	auth := config.AuthMode{Username: "user", Password: "secret"}
	request, err := http.NewRequest(http.MethodConnect, "https://proxy.invalid/", nil)
	if err != nil {
		t.Fatal(err)
	}
	credentials := base64.StdEncoding.EncodeToString([]byte("user:wrong"))
	request.Header.Set("Proxy-Authorization", "Basic "+credentials)
	if _, ok := authenticate(request, auth); ok {
		t.Fatal("wrong password was accepted")
	}
}

func TestProxyErrorStatus(t *testing.T) {
	if got := proxyErrorStatus(&net.DNSError{Name: "invalid.example", IsNotFound: true}); got != http.StatusBadGateway {
		t.Fatalf("DNS status = %d, want %d", got, http.StatusBadGateway)
	}
	if got := proxyErrorStatus(&net.AddrError{Err: "bad port", Addr: "x"}); got != http.StatusBadRequest {
		t.Fatalf("address status = %d, want %d", got, http.StatusBadRequest)
	}
}
