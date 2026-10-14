// Package web embeds the static web UI.
package web

import "embed"

// FS holds index.html, app.js, style.css and any other assets.
//
//go:embed *.html *.js *.css
var FS embed.FS
