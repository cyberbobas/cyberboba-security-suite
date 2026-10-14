package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cyberboba/internal/client"
)

func TestHTTPTransport(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":"t"}`))
	}))
	defer api.Close()
	s := New(client.New("", strings.TrimPrefix(api.URL, "http://"), ""))
	// single request
	resp, has := s.HandleHTTP([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if !has {
		t.Fatal("expected response")
	}
	var m map[string]interface{}
	json.Unmarshal(resp, &m)
	if m["result"] == nil {
		t.Fatalf("no result: %s", resp)
	}
	// notification only -> no response
	if _, has := s.HandleHTTP([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); has {
		t.Fatal("notification should not produce a response")
	}
	// batch
	resp, has = s.HandleHTTP([]byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`))
	if !has {
		t.Fatal("expected batch response")
	}
	var arr []map[string]interface{}
	if json.Unmarshal(resp, &arr); len(arr) != 2 {
		t.Fatalf("batch len=%d", len(arr))
	}
}

func TestServeRoundTrip(t *testing.T) {
	var gotRules []map[string]interface{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/status":
			w.Write([]byte(`{"version":"t","stats":{"active":1}}`))
		case "GET /api/rules":
			w.Write([]byte(`{"rules":[{"name":"a","action":"direct"},{"name":"Default","action":"direct"}]}`))
		case "PUT /api/rules":
			var in struct {
				Rules []map[string]interface{} `json:"rules"`
			}
			json.NewDecoder(r.Body).Decode(&in)
			gotRules = in.Rules
			w.Write([]byte(`{"rules":[]}`))
		case "GET /api/intercept/flows":
			w.Write([]byte(`{"flows":[],"total":0}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"nope"}`))
		}
	}))
	defer api.Close()
	s := New(client.New("", strings.TrimPrefix(api.URL, "http://"), ""))
	var out bytes.Buffer
	s.out = &out
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"status"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"add_rule","arguments":{"name":"new","apps":"curl, wget","action":"block"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"vpn_up","arguments":{"name":"x"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"nope"}`,
		`{"jsonrpc":"2.0","id":7,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":8,"method":"prompts/list"}`,
		`{"jsonrpc":"2.0","id":9,"method":"prompts/get","params":{"name":"route_app","arguments":{"app":"firefox","via":"home"}}}`,
		`{"jsonrpc":"2.0","id":10,"method":"resources/read","params":{"uri":"cyberboba://status"}}`,
	}, "\n") + "\n"
	if err := s.Serve(strings.NewReader(in)); err != nil {
		t.Fatal(err)
	}
	got := map[float64]map[string]interface{}{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad line %q", line)
		}
		if id, ok := m["id"].(float64); ok {
			got[id] = m
		}
	}
	if len(got) != 10 {
		t.Fatalf("responses=%d: %s", len(got), out.String())
	}
	if n := len(got[7]["result"].(map[string]interface{})["resources"].([]interface{})); n < 8 {
		t.Fatalf("resources=%d", n)
	}
	if n := len(got[8]["result"].(map[string]interface{})["prompts"].([]interface{})); n != 3 {
		t.Fatalf("prompts=%d", n)
	}
	msgs := got[9]["result"].(map[string]interface{})["messages"].([]interface{})
	if len(msgs) == 0 {
		t.Fatal("prompt get empty")
	}
	rc := got[10]["result"].(map[string]interface{})["contents"].([]interface{})
	if len(rc) == 0 || !strings.Contains(rc[0].(map[string]interface{})["text"].(string), `"active":1`) {
		t.Fatalf("resource read: %v", rc)
	}
	if got[1]["result"].(map[string]interface{})["protocolVersion"] != "2024-11-05" {
		t.Fatal("protocol negotiation")
	}
	if n := len(got[2]["result"].(map[string]interface{})["tools"].([]interface{})); n < 30 {
		t.Fatalf("tools=%d", n)
	}
	txt := got[3]["result"].(map[string]interface{})["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if !strings.Contains(txt, `"active": 1`) {
		t.Fatalf("status text %q", txt)
	}
	if len(gotRules) != 3 || gotRules[1]["name"] != "new" || gotRules[2]["name"] != "Default" {
		t.Fatalf("add_rule placement: %v", gotRules)
	}
	if apps, _ := gotRules[1]["apps"].([]interface{}); len(apps) != 2 {
		t.Fatalf("apps list parse: %v", gotRules[1]["apps"])
	}
	r5 := got[5]["result"].(map[string]interface{})
	if r5["isError"] != true {
		t.Fatalf("expected tool error: %v", r5)
	}
	if got[6]["error"] == nil {
		t.Fatal("expected method not found")
	}
}
