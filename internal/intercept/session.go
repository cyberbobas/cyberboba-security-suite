package intercept

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"cyberboba/internal/config"
)

// sessionFile is the on-disk representation of a saved capture.
type sessionFile struct {
	Version int           `json:"version"`
	Saved   time.Time     `json:"saved"`
	Flows   []sessionFlow `json:"flows"`
}

type sessionFlow struct {
	Meta     FlowDetail `json:"meta"`
	ReqBody  string     `json:"req_body_b64"`
	RespBody string     `json:"resp_body_b64"`
}

// SaveSession writes all stored flows (with bodies) to path. An empty path
// creates a timestamped file under dir.
func (e *Engine) SaveSession(dir, path string) (string, int, error) {
	flows := e.store.All()
	sf := sessionFile{Version: 1, Saved: time.Now()}
	for _, f := range flows {
		d := f.DetailCut(0)
		f.priv().mu.Lock()
		rb, pb := f.priv().reqBody, f.priv().respBody
		f.priv().mu.Unlock()
		sf.Flows = append(sf.Flows, sessionFlow{
			Meta:     d,
			ReqBody:  base64.StdEncoding.EncodeToString(rb),
			RespBody: base64.StdEncoding.EncodeToString(pb),
		})
	}
	if path == "" {
		if dir == "" {
			dir = "/var/lib/cyberboba/sessions"
		}
		path = filepath.Join(dir, "session-"+time.Now().Format("20060102-150405")+".json")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, err
	}
	data, err := json.MarshalIndent(sf, "", " ")
	if err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", 0, err
	}
	return path, len(sf.Flows), nil
}

// LoadSession reads a session file into the store. When replace is true the
// current flows are cleared first. Returns the number loaded.
func (e *Engine) LoadSession(path string, replace bool) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var sf sessionFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return 0, fmt.Errorf("parse session: %w", err)
	}
	if replace {
		e.store.Clear()
	}
	for _, s := range sf.Flows {
		f := &Flow{}
		m := s.Meta.Flow
		f.Time, f.DurationMS, f.Source, f.App, f.PID = m.Time, m.DurationMS, m.Source, m.App, m.PID
		f.Host, f.Port, f.TLS, f.InScope = m.Host, m.Port, m.TLS, m.InScope
		f.Intercepted, f.Edited, f.Rewritten = m.Intercepted, m.Edited, m.Rewritten
		f.Method, f.URL, f.Path, f.Proto = m.Method, m.URL, m.Path, m.Proto
		f.ReqHeaders, f.ReqSize, f.ReqBodyTruncated = m.ReqHeaders, m.ReqSize, m.ReqBodyTruncated
		f.Status, f.StatusText, f.RespHeaders = m.Status, m.StatusText, m.RespHeaders
		f.RespSize, f.RespBodyTruncated, f.ContentType, f.WebSocket = m.RespSize, m.RespBodyTruncated, m.ContentType, m.WebSocket
		f.State, f.Error = m.State, m.Error
		if b, err := base64.StdEncoding.DecodeString(s.ReqBody); err == nil {
			f.priv().reqBody = b
		}
		if b, err := base64.StdEncoding.DecodeString(s.RespBody); err == nil {
			f.priv().respBody = b
		}
		e.store.Add(f)
	}
	return len(sf.Flows), nil
}

// SessionInfo describes a saved session file.
type SessionInfo struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// ListSessions returns saved sessions in dir, newest first.
func ListSessions(dir string) []SessionInfo {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []SessionInfo{}
	}
	var out []SessionInfo
	for _, de := range entries {
		if de.IsDir() || filepath.Ext(de.Name()) != ".json" {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, SessionInfo{Path: filepath.Join(dir, de.Name()), Size: info.Size(), Modified: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Modified.After(out[j].Modified) })
	if out == nil {
		out = []SessionInfo{}
	}
	return out
}

// Rewrites returns the configured match & replace rules.
func (e *Engine) Rewrites() []config.Rewrite { return e.Config().Rewrites }
