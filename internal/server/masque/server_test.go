package masque

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

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

	extension, ok := newMasqueAuthenticator(auth).authenticate(request)
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
	if _, ok := newMasqueAuthenticator(auth).authenticate(request); ok {
		t.Fatal("wrong password was accepted")
	}
}

func TestDatagramBufferWritesContextIDZero(t *testing.T) {
	s := &Server{}
	s.datagramBufs.New = func() any { return make([]byte, len(contextIDZero)+8) }
	buf := s.getDatagramBuffer()
	if !bytes.Equal(buf[:len(contextIDZero)], contextIDZero) {
		t.Fatalf("context ID prefix = %x, want %x", buf[:len(contextIDZero)], contextIDZero)
	}
}

func TestTunnelIdleActivity(t *testing.T) {
	tunnel := &tunnel{}
	tunnel.lastActivity.Store(time.Now().Add(-2 * time.Second).UnixNano())
	if !tunnel.isIdle(time.Now(), time.Second) {
		t.Fatal("stale tunnel was not considered idle")
	}
	tunnel.touch()
	if tunnel.isIdle(time.Now(), time.Second) {
		t.Fatal("active tunnel was considered idle")
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
