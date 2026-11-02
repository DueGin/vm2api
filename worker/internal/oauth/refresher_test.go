package oauth

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dofastted/kin-gateway/worker/internal/credential"
	"github.com/imroc/req/v3"
)

func TestEnsureDeduplicatesConcurrentRefresh(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode refresh body: %v", err)
		}
		if body["refresh_token"] != "refresh-1" || body["grant_type"] != "refresh_token" {
			t.Errorf("unexpected refresh body: %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"access_token":"access-2","refresh_token":"refresh-2","expires_in":28800,"scope":"user:inference"}`))
	}))
	defer upstream.Close()

	store := credential.NewStore(filepath.Join(t.TempDir(), "credentials.json"))
	if _, err := store.Save(credential.Credential{
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		ExpiresAt:    time.Now().Add(-time.Minute).UnixMilli(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	var attempts []Attempt
	refresher := &Refresher{
		Store:     store,
		Client:    upstream.Client(),
		TokenURL:  upstream.URL,
		Skew:      5 * time.Minute,
		MaxTries:  1,
		OnAttempt: func(attempt Attempt) { attempts = append(attempts, attempt) },
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := refresher.Ensure(context.Background(), false)
			if err != nil {
				t.Errorf("Ensure: %v", err)
				return
			}
			if result.Credential.AccessToken != "access-2" {
				t.Errorf("access token = %q", result.Credential.AccessToken)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", calls.Load())
	}
	if len(attempts) != 2 || attempts[0].Phase != "start" || attempts[1].Phase != "success" ||
		attempts[0].AttemptID == "" || attempts[0].AttemptID != attempts[1].AttemptID {
		t.Fatalf("actual refresh notifications = %#v", attempts)
	}
	if _, err := refresher.Ensure(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 || calls.Load() != 1 {
		t.Fatalf("cached credential produced a refresh notification or network request")
	}
	current, err := store.Status()
	if err != nil {
		t.Fatal(err)
	}
	if current.RefreshToken != "refresh-2" || current.AccessToken != "access-2" {
		t.Fatalf("stored credential = %#v", current)
	}
}

func TestEnsurePreservesSetupTokenTypeAndFullScopes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"access_token":"access-2","refresh_token":"refresh-2","expires_in":28800,"scope":"user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"}`))
	}))
	defer upstream.Close()

	store := credential.NewStore(filepath.Join(t.TempDir(), "credentials.json"))
	if _, err := store.Save(credential.Credential{
		Type:         credential.TypeSetupToken,
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		ExpiresAt:    time.Now().Add(-time.Minute).UnixMilli(),
		Scopes: []string{
			"user:profile",
			"user:inference",
			"user:sessions:claude_code",
			"user:mcp_servers",
			"user:file_upload",
		},
	}, nil); err != nil {
		t.Fatal(err)
	}
	refresher := &Refresher{Store: store, Client: upstream.Client(), TokenURL: upstream.URL, MaxTries: 1}
	if _, err := refresher.Ensure(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	current, err := store.Status()
	if err != nil {
		t.Fatal(err)
	}
	if current.Type != credential.TypeSetupToken || current.RefreshToken != "refresh-2" {
		t.Fatalf("stored credential = %#v, want setup-token with rotated refresh", current)
	}
	if got := strings.Join(current.Scopes, " "); got != "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload" {
		t.Fatalf("scopes = %q", got)
	}
}

func TestEnsureDoesNotPersistAfterCancellation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		time.Sleep(100 * time.Millisecond)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"access_token":"too-late","refresh_token":"too-late","expires_in":28800}`))
	}))
	defer upstream.Close()
	store := credential.NewStore(filepath.Join(t.TempDir(), "credentials.json"))
	original, err := store.Save(credential.Credential{
		AccessToken:  "access-old",
		RefreshToken: "refresh-old",
		ExpiresAt:    time.Now().Add(-time.Minute).UnixMilli(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	refresher := &Refresher{Store: store, Client: upstream.Client(), TokenURL: upstream.URL, MaxTries: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = refresher.Ensure(ctx, true); err == nil {
		t.Fatal("expected cancellation error")
	}
	current, err := store.Status()
	if err != nil {
		t.Fatal(err)
	}
	if current.Generation != original.Generation || current.AccessToken != original.AccessToken {
		t.Fatalf("credential changed after cancellation: before=%#v after=%#v", original, current)
	}
}

// rawTokenServer answers one request with body (gzip when zipped) and returns the request bytes.
func rawTokenServer(t *testing.T, body string, zipped bool) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	captured := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			captured <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		var head strings.Builder
		length := 0
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				captured <- ""
				return
			}
			head.WriteString(line)
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				length, _ = strconv.Atoi(strings.TrimSpace(line[len("content-length:"):]))
			}
			if line == "\r\n" {
				break
			}
		}
		payload := make([]byte, length)
		_, _ = io.ReadFull(reader, payload)
		out := []byte(body)
		encoding := ""
		if zipped {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(out)
			_ = zw.Close()
			out = buf.Bytes()
			encoding = "Content-Encoding: gzip\r\n"
		}
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n%sContent-Length: %d\r\n\r\n", encoding, len(out))
		_, _ = conn.Write(out)
		captured <- head.String() + string(payload)
	}()
	return ln.Addr().String(), captured
}

func TestRefreshRequestMatchesCLIAxiosWire(t *testing.T) {
	addr, captured := rawTokenServer(t, `{"access_token":"access-2","refresh_token":"refresh-2","expires_in":28800}`, true)
	store := credential.NewStore(filepath.Join(t.TempDir(), "credentials.json"))
	if _, err := store.Save(credential.Credential{
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		ExpiresAt:    time.Now().Add(-time.Minute).UnixMilli(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	refresher := &Refresher{
		Store: store,
		// Production's slot client: req/v3 transport (header order) with auto-decompress.
		Client:   req.C().EnableAutoDecompress().GetClient(),
		TokenURL: "http://" + addr + "/v1/oauth/token",
		MaxTries: 1,
	}
	result, err := refresher.Ensure(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Credential.AccessToken != "access-2" {
		t.Fatalf("gzip token response not decoded: %#v", result.Credential)
	}
	raw := <-captured
	head, body, _ := strings.Cut(raw, "\r\n\r\n")
	wantBody := `{"grant_type":"refresh_token","refresh_token":"refresh-1","client_id":"` + DefaultClientID +
		`","scope":"user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"}`
	if body != wantBody {
		t.Fatalf("body\n got %s\nwant %s", body, wantBody)
	}
	want := []string{
		"POST /v1/oauth/token HTTP/1.1",
		"Accept: application/json, text/plain, */*",
		"Accept-Encoding: gzip, compress, deflate, br",
		"Content-Type: application/json",
		"User-Agent: axios/1.15.0",
		"Connection: keep-alive",
		"Host: " + addr,
		"Content-Length: " + strconv.Itoa(len(wantBody)),
	}
	if got := strings.Split(head, "\r\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("request head\n got %q\nwant %q", got, want)
	}
}

func TestRefreshScopeFollowsTheCLI(t *testing.T) {
	full := "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	// cli-node with a ["user:inference","user:profile"] token sent the full default set.
	if got := refreshScope(credential.Credential{Scopes: []string{"user:inference", "user:profile"}}); got != full {
		t.Fatalf("subscriber scope = %q", got)
	}
	if got := refreshScope(credential.Credential{Scopes: []string{"org:create_api_key", "user:profile"}}); got != "org:create_api_key user:profile" {
		t.Fatalf("console scope = %q", got)
	}
}
