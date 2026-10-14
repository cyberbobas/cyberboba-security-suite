package intercept

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// HAR builds a HTTP Archive 1.2 document from flows.
func HAR(flows []*Flow) []byte {
	type nv struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type entry struct {
		Started         string                 `json:"startedDateTime"`
		Time            int64                  `json:"time"`
		Request         map[string]interface{} `json:"request"`
		Response        map[string]interface{} `json:"response"`
		Cache           map[string]interface{} `json:"cache"`
		Timings         map[string]int64       `json:"timings"`
		ServerIPAddress string                 `json:"serverIPAddress,omitempty"`
		Comment         string                 `json:"comment,omitempty"`
	}
	var entries []entry
	for _, fl := range flows {
		d := fl.Detail()
		if d.Method == "" {
			continue
		}
		var reqH, respH []nv
		for _, h := range d.ReqHeaders {
			reqH = append(reqH, nv{h[0], h[1]})
		}
		for _, h := range d.RespHeaders {
			respH = append(respH, nv{h[0], h[1]})
		}
		var query []nv
		if u, err := url.Parse(d.URL); err == nil {
			for k, vs := range u.Query() {
				for _, v := range vs {
					query = append(query, nv{k, v})
				}
			}
		}
		if reqH == nil {
			reqH = []nv{}
		}
		if respH == nil {
			respH = []nv{}
		}
		if query == nil {
			query = []nv{}
		}
		req := map[string]interface{}{
			"method": d.Method, "url": d.URL, "httpVersion": d.Proto, "cookies": []nv{}, "headers": reqH,
			"queryString": query, "headersSize": -1, "bodySize": d.ReqSize,
		}
		if d.ReqBody != "" {
			pd := map[string]interface{}{"mimeType": headerValue(d.ReqHeaders, "Content-Type"), "text": d.ReqBody}
			if d.ReqBodyB64 {
				pd["encoding"] = "base64"
			}
			req["postData"] = pd
		}
		content := map[string]interface{}{"size": d.RespSize, "mimeType": d.ContentType, "text": d.RespBody}
		if d.RespBodyB64 {
			content["encoding"] = "base64"
		}
		resp := map[string]interface{}{
			"status": d.Status, "statusText": strings.TrimPrefix(d.StatusText, fmt.Sprintf("%d ", d.Status)),
			"httpVersion": d.Proto, "cookies": []nv{}, "headers": respH, "content": content,
			"redirectURL": headerValue(d.RespHeaders, "Location"), "headersSize": -1, "bodySize": d.RespSize,
		}
		entries = append(entries, entry{
			Started: d.Time.Format(time.RFC3339Nano), Time: d.DurationMS, Request: req, Response: resp,
			Cache: map[string]interface{}{}, Timings: map[string]int64{"send": 0, "wait": d.DurationMS, "receive": 0},
			Comment: fmt.Sprintf("cyberboba flow %d app=%s source=%s state=%s", d.ID, d.App, d.Source, d.State),
		})
	}
	if entries == nil {
		entries = []entry{}
	}
	doc := map[string]interface{}{"log": map[string]interface{}{
		"version": "1.2", "creator": map[string]string{"name": "cyberboba", "version": "0.2"}, "entries": entries}}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return b
}

func headerValue(hs []Header, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// Curl renders a flow as a curl command.
func Curl(f *Flow) string {
	d := f.Detail()
	var b strings.Builder
	b.WriteString("curl -i")
	if d.TLS {
		b.WriteString(" -k")
	}
	if d.Method != "GET" {
		b.WriteString(" -X " + shellQuote(d.Method))
	}
	b.WriteString(" " + shellQuote(d.URL))
	for _, h := range d.ReqHeaders {
		if strings.EqualFold(h[0], "Host") || strings.EqualFold(h[0], "Content-Length") {
			continue
		}
		b.WriteString(" \\\n  -H " + shellQuote(h[0]+": "+h[1]))
	}
	if d.ReqBody != "" {
		if d.ReqBodyB64 {
			raw, _ := base64.StdEncoding.DecodeString(d.ReqBody)
			b.WriteString(" \\\n  --data-binary " + shellQuote(string(raw)))
		} else {
			b.WriteString(" \\\n  --data-binary " + shellQuote(d.ReqBody))
		}
	}
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
