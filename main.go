package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookieName = "piccolo_session"
	tunnelTimeout     = 30 * time.Second
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "piccolo: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("missing command")
	}
	switch args[0] {
	case "tunnel":
		return runTunnel(args[1:], stdin, stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stderr)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: piccolo tunnel [options] <host[:port]>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "options:")
	fmt.Fprintln(w, "  --api URL              Piccolo portal/API origin (or PICCOLO_API)")
	fmt.Fprintln(w, "  --username USER        username for password login (or PICCOLO_USERNAME)")
	fmt.Fprintln(w, "  --password PASSWORD    password for login (or PICCOLO_PASSWORD)")
	fmt.Fprintln(w, "  --session-cookie VAL   existing piccolo_session cookie value/header")
	fmt.Fprintln(w, "  --port PORT            target remote port (default 443)")
	fmt.Fprintln(w, "  --dial-address ADDR    physical host:port to dial while preserving SNI")
	fmt.Fprintln(w, "  --ca-cert PATH         append PEM root CA for server verification")
}

func runTunnel(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tunnel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		printUsage(stderr)
	}
	apiOrigin := fs.String("api", getenv("PICCOLO_API"), "Piccolo portal/API origin")
	username := fs.String("username", getenv("PICCOLO_USERNAME"), "Piccolo username")
	password := fs.String("password", "", "Piccolo password")
	sessionCookie := fs.String("session-cookie", "", "existing piccolo_session cookie")
	portFlag := fs.Int("port", 0, "target remote port")
	dialAddress := fs.String("dial-address", "", "physical host:port to dial")
	caCertPath := fs.String("ca-cert", "", "PEM root CA for server verification")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	passwordValue := *password
	if strings.TrimSpace(passwordValue) == "" {
		passwordValue = getenv("PICCOLO_PASSWORD")
	}
	sessionCookieValue := *sessionCookie
	if strings.TrimSpace(sessionCookieValue) == "" {
		sessionCookieValue = getenv("PICCOLO_SESSION_COOKIE")
	}
	if fs.NArg() != 1 {
		return errors.New("tunnel requires exactly one host target")
	}
	targetHost, targetPort, err := parseTarget(fs.Arg(0), *portFlag)
	if err != nil {
		return err
	}
	api, err := parseAPIOrigin(*apiOrigin)
	if err != nil {
		return err
	}

	roots, err := rootPool(*caCertPath)
	if err != nil {
		return err
	}
	jar, _ := cookiejar.New(nil)
	client := newAPIClient(jar, roots)
	if strings.TrimSpace(sessionCookieValue) != "" {
		seedSessionCookie(jar, api, sessionCookieValue)
	} else {
		if strings.TrimSpace(*username) == "" || passwordValue == "" {
			return errors.New("set --session-cookie or --username/--password")
		}
		if err := login(client, api, *username, passwordValue); err != nil {
			return err
		}
	}
	csrf, err := fetchCSRF(client, api)
	if err != nil {
		return err
	}
	cert, err := requestTunnelCertificate(client, api, csrf, targetHost, targetPort)
	if err != nil {
		return err
	}
	addr := *dialAddress
	if strings.TrimSpace(addr) == "" {
		addr = net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	}
	conn, err := tls.DialWithDialer(newTunnelDialer(), "tcp", addr, &tls.Config{
		ServerName:   targetHost,
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("open tunnel: %w", err)
	}
	defer conn.Close()

	return relayTunnel(stdin, stdout, conn)
}

func newTunnelDialer() *net.Dialer {
	return &net.Dialer{Timeout: tunnelTimeout}
}

func newAPIClient(jar http.CookieJar, roots *x509.CertPool) *http.Client {
	client := &http.Client{Jar: jar, Timeout: tunnelTimeout}
	if roots == nil {
		return client
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
	}
	client.Transport = transport
	return client
}

func relayTunnel(stdin io.Reader, stdout io.Writer, conn net.Conn) error {
	errCh := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(conn, stdin)
		if cw, ok := any(conn).(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		errCh <- copyErr
	}()
	_, outErr := io.Copy(stdout, conn)
	_ = conn.Close()
	if outErr != nil && !isTunnelCloseError(outErr) {
		return outErr
	}
	select {
	case inErr := <-errCh:
		if inErr != nil && !isTunnelCloseError(inErr) {
			return inErr
		}
	default:
	}
	return nil
}

func isTunnelCloseError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

func login(client *http.Client, api *url.URL, username, password string) error {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req, err := http.NewRequest(http.MethodPost, apiURL(api, "/api/v1/auth/login"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("login failed: %s: %s", resp.Status, readErrorBody(resp.Body))
	}
	return nil
}

func fetchCSRF(client *http.Client, api *url.URL) (string, error) {
	resp, err := client.Get(apiURL(api, "/api/v1/auth/csrf"))
	if err != nil {
		return "", fmt.Errorf("fetch csrf: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("fetch csrf failed: %s: %s", resp.Status, readErrorBody(resp.Body))
	}
	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("parse csrf: %w", err)
	}
	if parsed.Token == "" {
		return "", errors.New("csrf response missing token")
	}
	return parsed.Token, nil
}

func requestTunnelCertificate(client *http.Client, api *url.URL, csrf, host string, port int) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return tls.Certificate{}, err
	}
	reqBody, _ := json.Marshal(map[string]any{
		"host":                  host,
		"remote_port":           port,
		"public_key_pem":        string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		"requested_ttl_seconds": int64(3600),
	})
	req, err := http.NewRequest(http.MethodPost, apiURL(api, "/api/v1/tunnels/certificates"), bytes.NewReader(reqBody))
	if err != nil {
		return tls.Certificate{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := client.Do(req)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("request tunnel certificate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return tls.Certificate{}, fmt.Errorf("request tunnel certificate failed: %s: %s", resp.Status, readErrorBody(resp.Body))
	}
	var parsed struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return tls.Certificate{}, fmt.Errorf("parse tunnel certificate: %w", err)
	}
	if parsed.CertificatePEM == "" {
		return tls.Certificate{}, errors.New("tunnel certificate response missing certificate_pem")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair([]byte(parsed.CertificatePEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load tunnel client certificate: %w", err)
	}
	return cert, nil
}

func parseAPIOrigin(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("--api is required")
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("--api must start with https:// or http://")
	}
	if u.Host == "" {
		return nil, errors.New("--api must include a host")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, errors.New("--api http:// origins are only allowed for localhost or loopback addresses")
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func apiURL(api *url.URL, path string) string {
	cp := *api
	cp.Path = strings.TrimRight(cp.Path, "/") + path
	cp.RawQuery = ""
	cp.Fragment = ""
	return cp.String()
}

func parseTarget(raw string, explicitPort int) (string, int, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", 0, errors.New("empty target host")
	}
	if strings.Contains(target, "://") {
		return "", 0, errors.New("target must be a host, not a URL")
	}
	host := target
	port := explicitPort
	if h, p, err := net.SplitHostPort(target); err == nil {
		host = h
		parsed, err := strconv.Atoi(p)
		if err != nil {
			return "", 0, fmt.Errorf("invalid target port %q", p)
		}
		if explicitPort != 0 && explicitPort != parsed {
			return "", 0, errors.New("--port conflicts with target host:port")
		}
		port = parsed
	} else if strings.Count(target, ":") == 1 {
		h, p, _ := strings.Cut(target, ":")
		parsed, err := strconv.Atoi(p)
		if err != nil {
			return "", 0, fmt.Errorf("invalid target port %q", p)
		}
		if explicitPort != 0 && explicitPort != parsed {
			return "", 0, errors.New("--port conflicts with target host:port")
		}
		host = h
		port = parsed
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" {
		return "", 0, errors.New("empty target host")
	}
	if port == 0 {
		port = 443
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("invalid target port %d", port)
	}
	return host, port, nil
}

func seedSessionCookie(jar http.CookieJar, api *url.URL, raw string) {
	raw = strings.TrimSpace(raw)
	if name, value, ok := strings.Cut(raw, ":"); ok && isCookieHeaderName(name) {
		raw = strings.TrimSpace(value)
	}
	if raw == "" {
		return
	}
	var cookies []*http.Cookie
	var bareValue string
	foundNamedSession := false
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			if bareValue == "" {
				bareValue = part
			}
			continue
		}
		if strings.TrimSpace(name) == sessionCookieName {
			foundNamedSession = true
			cookies = append(cookies, &http.Cookie{Name: sessionCookieName, Value: strings.TrimSpace(value)})
		}
	}
	if !foundNamedSession && bareValue != "" {
		cookies = append(cookies, &http.Cookie{Name: sessionCookieName, Value: bareValue})
	}
	jar.SetCookies(api, cookies)
}

func isCookieHeaderName(name string) bool {
	name = strings.TrimSpace(name)
	return strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "Set-Cookie")
}

func rootPool(caCertPath string) (*x509.CertPool, error) {
	if strings.TrimSpace(caCertPath) == "" {
		return nil, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	data, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificates found in %s", caCertPath)
	}
	return roots, nil
}

func readErrorBody(r io.Reader) string {
	data, _ := io.ReadAll(io.LimitReader(r, 4<<10))
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "<empty body>"
	}
	return text
}

func getenv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
