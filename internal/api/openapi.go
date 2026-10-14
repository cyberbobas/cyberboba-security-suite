package api

import _ "embed"

// openAPISpec is served at /api/openapi.json for agents and tooling.
//
//go:embed openapi.json
var openAPISpec []byte
