package upstream

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// keyShareX25519 prefixes the 32-byte x25519 public key in the key_share extension.
var keyShareX25519 = []byte{0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20}

func loadReferenceHello(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/cli-node-2.1.303-clienthello.hex")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// maskHello zeroes the per-connection random, legacy session id and x25519 key.
func maskHello(t *testing.T, record []byte) []byte {
	t.Helper()
	out := append([]byte(nil), record...)
	if len(out) < 76 || out[0] != 0x16 || out[5] != 0x01 {
		t.Fatalf("not a ClientHello record: % x", out[:min(len(out), 16)])
	}
	clear(out[11:43]) // random
	sidLen := int(out[43])
	clear(out[44 : 44+sidLen])
	at := bytes.Index(out, keyShareX25519)
	if at < 0 {
		t.Fatalf("no x25519 key share")
	}
	key := at + len(keyShareX25519)
	clear(out[key : key+32])
	return out
}

// captureHello makes one HTTPS request with the slot client and returns the
// first TLS record it sends, without completing the handshake.
func captureHello(t *testing.T, url string, oauth bool) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		head := make([]byte, 5)
		if _, err := io.ReadFull(conn, head); err != nil {
			got <- nil
			return
		}
		body := make([]byte, int(head[3])<<8|int(head[4]))
		if _, err := io.ReadFull(conn, body); err != nil {
			got <- nil
			return
		}
		got <- append(head, body...)
	}()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	client := slotCLIClient(3*time.Second, dial)
	if oauth {
		client = client.EnableAutoDecompress()
	}
	_, _ = client.GetClient().Get(url)
	record := <-got
	if record == nil {
		t.Fatal("no ClientHello captured")
	}
	return record
}

func TestSlotClientHelloMatchesCLINode(t *testing.T) {
	ref := loadReferenceHello(t)
	for _, oauth := range []bool{true, false} {
		got := captureHello(t, "https://platform.claude.com/v1/oauth/token", oauth)
		if len(got) != len(ref) {
			t.Fatalf("oauth=%v: ClientHello record is %d bytes, cli-node sends %d", oauth, len(got), len(ref))
		}
		if !bytes.Equal(maskHello(t, got), maskHello(t, ref)) {
			t.Fatalf("oauth=%v: ClientHello differs from cli-node\n got % x\nwant % x", oauth, maskHello(t, got), maskHello(t, ref))
		}
		if got[43] != 32 {
			t.Fatalf("legacy session id is %d bytes, cli-node sends 32", got[43])
		}
	}
}

// The handshake for another host keeps the same shape; only SNI and padding move.
func TestSlotClientHelloShapeForAPIHost(t *testing.T) {
	got := captureHello(t, "https://api.anthropic.com/api/oauth/usage", true)
	if len(got) != 517 {
		t.Fatalf("BoringSSL pads the handshake to 512 bytes; record is %d", len(got))
	}
	spec, err := (&utls.Fingerprinter{}).FingerprintClientHello(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			if len(alpn.AlpnProtocols) != 1 || alpn.AlpnProtocols[0] != "http/1.1" {
				t.Fatalf("ALPN %v, cli-node offers only http/1.1", alpn.AlpnProtocols)
			}
			return
		}
	}
	t.Fatal("no ALPN extension")
}
