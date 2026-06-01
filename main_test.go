package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		flagPort int
		host     string
		port     int
	}{
		{name: "default port", raw: "ssh-demo.example.com", host: "ssh-demo.example.com", port: 443},
		{name: "target port", raw: "ssh-demo.example.com:8443", host: "ssh-demo.example.com", port: 8443},
		{name: "flag port", raw: "ssh-demo.example.com", flagPort: 9443, host: "ssh-demo.example.com", port: 9443},
		{name: "bracketed ipv6", raw: "[2001:db8::1]:443", host: "2001:db8::1", port: 443},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := parseTarget(tc.raw, tc.flagPort)
			if err != nil {
				t.Fatalf("parseTarget: %v", err)
			}
			if host != tc.host || port != tc.port {
				t.Fatalf("parseTarget = %q:%d, want %q:%d", host, port, tc.host, tc.port)
			}
		})
	}
}

func TestParseTargetRejectsURL(t *testing.T) {
	if _, _, err := parseTarget("https://ssh-demo.example.com", 0); err == nil {
		t.Fatalf("expected URL target to be rejected")
	}
}

func TestTunnelHelpDoesNotExposeSecretEnv(t *testing.T) {
	t.Setenv("PICCOLO_PASSWORD", "supersecret")
	t.Setenv("PICCOLO_SESSION_COOKIE", "sessionsecret")
	var stdout, stderr bytes.Buffer

	err := run([]string{"tunnel", "-h"}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run help: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if got := stderr.String(); strings.Contains(got, "supersecret") || strings.Contains(got, "sessionsecret") {
		t.Fatalf("help leaked secret env values: %q", got)
	}
}

func TestTunnelParseErrorDoesNotExposeSecretEnv(t *testing.T) {
	t.Setenv("PICCOLO_PASSWORD", "supersecret")
	t.Setenv("PICCOLO_SESSION_COOKIE", "sessionsecret")
	var stdout, stderr bytes.Buffer

	err := run([]string{"tunnel", "--port", "nope", "ssh-demo.example.com"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if got := stderr.String(); strings.Contains(got, "supersecret") || strings.Contains(got, "sessionsecret") {
		t.Fatalf("parse error leaked secret env values: %q", got)
	}
}

func TestParseAPIOriginRejectsNonLoopbackHTTP(t *testing.T) {
	if _, err := parseAPIOrigin("http://portal.example.test"); err == nil {
		t.Fatalf("expected non-loopback http API origin to be rejected")
	}
}

func TestParseAPIOriginAllowsHTTPSAndLoopbackHTTP(t *testing.T) {
	tests := []string{
		"https://portal.example.test",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, err := parseAPIOrigin(raw); err != nil {
				t.Fatalf("parseAPIOrigin(%q): %v", raw, err)
			}
		})
	}
}

func TestNewTunnelDialerUsesTimeout(t *testing.T) {
	dialer := newTunnelDialer()
	if dialer.Timeout != tunnelTimeout {
		t.Fatalf("dialer.Timeout = %s, want %s", dialer.Timeout, tunnelTimeout)
	}
}

func TestNewAPIClientAppliesRootPoolToTransport(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	roots := x509.NewCertPool()

	client := newAPIClient(jar, roots)
	if client.Jar != jar {
		t.Fatalf("client.Jar was not preserved")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatalf("TLSClientConfig is nil")
	}
	if transport.TLSClientConfig.RootCAs != roots {
		t.Fatalf("RootCAs was not set to the supplied pool")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want %x", transport.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
}

func TestNewAPIClientUsesDefaultTransportWithoutRootPool(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}

	client := newAPIClient(jar, nil)
	if client.Transport != nil {
		t.Fatalf("client.Transport = %T, want nil default transport", client.Transport)
	}
}

func TestRelayTunnelReturnsWhenRemoteClosesBeforeStdin(t *testing.T) {
	local, remote := net.Pipe()
	stdin, stdinWriter := io.Pipe()
	defer stdin.Close()
	defer stdinWriter.Close()
	defer remote.Close()

	done := make(chan error, 1)
	go func() {
		done <- relayTunnel(stdin, io.Discard, local)
	}()
	_ = remote.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("relayTunnel returned error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("relayTunnel did not return after remote close")
	}
}

func TestSeedSessionCookieAcceptsCookieHeader(t *testing.T) {
	api, err := url.Parse("https://portal.example.test")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}

	seedSessionCookie(jar, api, "Cookie: other=ignored; piccolo_session=abc123")

	if got := sessionCookieValue(jar, api); got != "abc123" {
		t.Fatalf("session cookie = %q, want %q", got, "abc123")
	}
}

func TestSeedSessionCookieAcceptsCookieHeaderWithBareValue(t *testing.T) {
	api, err := url.Parse("https://portal.example.test")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}

	seedSessionCookie(jar, api, "cookie: abc123")

	if got := sessionCookieValue(jar, api); got != "abc123" {
		t.Fatalf("session cookie = %q, want %q", got, "abc123")
	}
}

func TestSeedSessionCookieIgnoresAttributesAfterNamedCookie(t *testing.T) {
	api, err := url.Parse("https://portal.example.test")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}

	seedSessionCookie(jar, api, "piccolo_session=abc123; Path=/; HttpOnly")

	if got := sessionCookieValue(jar, api); got != "abc123" {
		t.Fatalf("session cookie = %q, want %q", got, "abc123")
	}
}

func TestSeedSessionCookieAcceptsSetCookieHeader(t *testing.T) {
	api, err := url.Parse("https://portal.example.test")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}

	seedSessionCookie(jar, api, "Set-Cookie: piccolo_session=abc123; Path=/; HttpOnly")

	if got := sessionCookieValue(jar, api); got != "abc123" {
		t.Fatalf("session cookie = %q, want %q", got, "abc123")
	}
}

func sessionCookieValue(jar *cookiejar.Jar, api *url.URL) string {
	for _, cookie := range jar.Cookies(api) {
		if cookie.Name == sessionCookieName {
			return cookie.Value
		}
	}
	return ""
}
