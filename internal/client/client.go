// Package client is a small HTTP client for the cyberbobad API, shared by the
// CLI and the MCP server.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client talks to the daemon over a unix socket or TCP.
type Client struct {
	Socket string // unix socket path (used when Addr is empty)
	Addr   string // host:port
	Token  string
	hc     *http.Client
}

// New creates a client.
func New(socket, addr, token string) *Client {
	c := &Client{Socket: socket, Addr: addr, Token: token}
	tr := &http.Transport{}
	if addr == "" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
	}
	c.hc = &http.Client{Transport: tr, Timeout: 5 * time.Minute}
	return c
}

func (c *Client) base() string {
	if c.Addr != "" {
		return "http://" + c.Addr
	}
	return "http://cyberboba"
}

// Do performs a request and returns the raw body; API errors become Go errors.
func (c *Client) Do(method, path string, body interface{}) ([]byte, error) {
	var rd io.Reader
	ct := "application/json"
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
			ct = "text/plain"
		case []byte:
			rd = bytes.NewReader(b)
			ct = "application/octet-stream"
		default:
			enc, err := json.Marshal(b)
			if err != nil {
				return nil, err
			}
			rd = bytes.NewReader(enc)
		}
	}
	req, err := http.NewRequest(method, c.base()+path, rd)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach cyberbobad: %v (is the service running?)", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return nil, fmt.Errorf("%s", e.Error)
	}
	return data, nil
}

// JSON performs a request and decodes the JSON response into v.
func (c *Client) JSON(method, path string, body, v interface{}) error {
	data, err := c.Do(method, path, body)
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(data, v)
}

// Stream opens the SSE event stream and calls fn for each event.
func (c *Client) Stream(ctx context.Context, fn func(typ string, data []byte)) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base()+"/api/events", nil)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := *c.hc
	hc.Timeout = 0
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 64*1024)
	typ := ""
	rd := resp.Body
	tmp := make([]byte, 32*1024)
	for {
		n, err := rd.Read(tmp)
		buf = append(buf, tmp[:n]...)
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			line := string(buf[:i])
			buf = buf[i+1:]
			switch {
			case strings.HasPrefix(line, "event: "):
				typ = line[7:]
			case strings.HasPrefix(line, "data: "):
				fn(typ, []byte(line[6:]))
			}
		}
		if err != nil {
			return err
		}
	}
}
