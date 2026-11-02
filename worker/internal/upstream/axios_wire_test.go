package upstream

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dofastted/kin-gateway/worker/internal/credential"
	"github.com/imroc/req/v3"
)

// oneRequestHead serves a single request with an empty JSON object and returns its head.
func oneRequestHead(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	head := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			head <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		var b strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
			b.WriteString(line)
		}
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
		head <- strings.TrimRight(b.String(), "\r\n")
	}()
	return ln.Addr().String(), head
}

func axiosClient(t *testing.T, addr string) *Client {
	t.Helper()
	store := credential.NewStore(filepath.Join(t.TempDir(), "credentials.json"))
	if _, err := store.Save(credential.Credential{
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		ExpiresAt:    time.Now().Add(time.Hour).UnixMilli(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("http://" + addr)
	return &Client{HTTP: req.C().EnableAutoDecompress().GetClient(), Store: store, AnthropicBase: base}
}

// Captured from cli-node 2.1.303 on the native-slot path (usage.ts / getOauthProfileFromOauthToken).
func TestUsageAndProfileMatchCLIAxiosWire(t *testing.T) {
	cases := []struct {
		path, ua, beta string
		want           []string
	}{
		{"/api/oauth/usage", "claude-code/2.1.303", "oauth-2025-04-20", []string{
			"GET /api/oauth/usage HTTP/1.1",
			"Accept: application/json, text/plain, */*",
			"Accept-Encoding: gzip, compress, deflate, br",
			"Authorization: Bearer access-1",
			"Content-Type: application/json",
			"User-Agent: claude-code/2.1.303",
			"anthropic-beta: oauth-2025-04-20",
			"Connection: keep-alive",
		}},
		{"/api/oauth/profile", "axios/1.15.0", "", []string{
			"GET /api/oauth/profile HTTP/1.1",
			"Accept: application/json, text/plain, */*",
			"Accept-Encoding: gzip, compress, deflate, br",
			"Authorization: Bearer access-1",
			"Content-Type: application/json",
			"User-Agent: axios/1.15.0",
			"Connection: keep-alive",
		}},
	}
	for _, tc := range cases {
		addr, head := oneRequestHead(t)
		response, err := axiosClient(t, addr).GetCLIAxios(context.Background(), tc.path, tc.ua, tc.beta)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		want := append(tc.want, "Host: "+addr)
		if got := strings.Split(<-head, "\r\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("%s head\n got %q\nwant %q", tc.path, got, want)
		}
	}
}
