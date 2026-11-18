package oauth

import (
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/imroc/req/v3"
	"github.com/klauspost/compress/zstd"
)

// EnableResponseDecoding keeps the raw body and headers for unsupported codings.
// req/v3's automatic decompressor discards them, preventing callers from
// classifying the error or closing the body.
func EnableResponseDecoding(client *req.Client) *req.Client {
	client.DisableAutoDecompress()
	client.GetTransport().WrapRoundTripFunc(func(next http.RoundTripper) req.HttpRoundTripFunc {
		return func(request *http.Request) (*http.Response, error) {
			response, err := next.RoundTrip(request)
			if err != nil {
				return nil, err
			}
			return response, decodeResponseBody(response)
		}
	})
	return client
}

func responseEncoding(headers http.Header) string {
	return strings.ToLower(strings.TrimSpace(strings.Join(headers.Values("Content-Encoding"), ",")))
}

func IsIdentityEncoding(headers http.Header) bool {
	encoding := responseEncoding(headers)
	return encoding == "" || encoding == "identity"
}

type decodedBody struct {
	io.Reader
	closeRaw     func() error
	closeDecoder func() error
}

func (body decodedBody) Close() error {
	if body.closeDecoder == nil {
		return body.closeRaw()
	}
	return errors.Join(body.closeDecoder(), body.closeRaw())
}

func decodeResponseBody(response *http.Response) error {
	raw := response.Body
	if raw == nil || raw == http.NoBody {
		return nil
	}
	decoded := decodedBody{closeRaw: raw.Close}
	switch responseEncoding(response.Header) {
	case "gzip":
		reader, err := gzip.NewReader(raw)
		if err != nil {
			_ = raw.Close()
			return fmt.Errorf("decode OAuth gzip response: %w", err)
		}
		decoded.Reader, decoded.closeDecoder = reader, reader.Close
	case "deflate":
		reader := flate.NewReader(raw)
		decoded.Reader, decoded.closeDecoder = reader, reader.Close
	case "br":
		decoded.Reader = brotli.NewReader(raw)
	case "zstd":
		reader, err := zstd.NewReader(raw)
		if err != nil {
			_ = raw.Close()
			return fmt.Errorf("decode OAuth zstd response: %w", err)
		}
		decoded.Reader = reader
		decoded.closeDecoder = func() error {
			reader.Close()
			return nil
		}
	default:
		return nil
	}
	response.Body = decoded
	response.Header.Del("Content-Encoding")
	response.Header.Del("Content-Length")
	response.ContentLength = -1
	response.Uncompressed = true
	return nil
}
