// Package apps discovers installed desktop applications by parsing freedesktop
// .desktop entries, so the UI can offer human-friendly app names (e.g. "Firefox
// Web Browser") instead of raw process names. Each app carries a suggested
// match keyword for a `cmd:` rule, which matches the process command line and
// is far more forgiving than the kernel comm name.
package apps

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// App is one installed application.
type App struct {
	Name       string   `json:"name"`
	Comment    string   `json:"comment,omitempty"`
	Exec       string   `json:"exec,omitempty"`
	Binary     string   `json:"binary,omitempty"`
	Keyword    string   `json:"keyword"` // suggested cmd: match stem
	Categories []string `json:"categories,omitempty"`
	Icon       string   `json:"icon,omitempty"`
	Path       string   `json:"path,omitempty"`
}

// stemAlias maps a launcher binary to the stem that actually appears in the
// command line of the app's real (network-doing) processes.
var stemAlias = map[string]string{
	"google-chrome": "chrome", "google-chrome-stable": "chrome", "google-chrome-beta": "chrome", "google-chrome-unstable": "chrome",
	"microsoft-edge": "msedge", "microsoft-edge-stable": "msedge", "microsoft-edge-beta": "msedge",
	"brave-browser": "brave", "brave-browser-stable": "brave",
	"chromium-browser": "chromium", "vivaldi-stable": "vivaldi", "opera": "opera",
}

func appDirs() []string {
	seen := map[string]bool{}
	var dirs []string
	add := func(d string) {
		if d == "" {
			return
		}
		d = filepath.Clean(d)
		if !seen[d] {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	dataDirs := os.Getenv("XDG_DATA_DIRS")
	if dataDirs == "" {
		dataDirs = "/usr/local/share:/usr/share"
	}
	for _, d := range strings.Split(dataDirs, ":") {
		add(filepath.Join(d, "applications"))
	}
	add("/usr/share/applications")
	add("/usr/local/share/applications")
	add("/var/lib/flatpak/exports/share/applications")
	add("/var/lib/snapd/desktop/applications")
	// per-user locations (the daemon usually runs as root; scan every home)
	if homes, err := filepath.Glob("/home/*"); err == nil {
		for _, h := range homes {
			add(filepath.Join(h, ".local/share/applications"))
			add(filepath.Join(h, ".local/share/flatpak/exports/share/applications"))
		}
	}
	add(filepath.Join(os.Getenv("HOME"), ".local/share/applications"))
	return dirs
}

// List returns installed applications, de-duplicated by name and sorted.
func List() []App {
	byName := map[string]App{}
	for _, dir := range appDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			app, ok := parse(filepath.Join(dir, e.Name()))
			if !ok {
				continue
			}
			key := strings.ToLower(app.Name)
			if cur, exists := byName[key]; !exists || (cur.Keyword == "" && app.Keyword != "") {
				byName[key] = app
			}
		}
	}
	out := make([]App, 0, len(byName))
	for _, a := range byName {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func parse(path string) (App, bool) {
	f, err := os.Open(path)
	if err != nil {
		return App{}, false
	}
	defer f.Close()
	inEntry := false
	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			inEntry = line == "[Desktop Entry]"
			continue
		}
		if !inEntry {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		// ignore localized variants beyond the default (Name[ru] etc.)
		if strings.ContainsAny(k, "[") {
			continue
		}
		if _, ok := kv[k]; !ok {
			kv[k] = strings.TrimSpace(line[i+1:])
		}
	}
	if kv["Type"] != "" && kv["Type"] != "Application" {
		return App{}, false
	}
	if truthy(kv["NoDisplay"]) || truthy(kv["Hidden"]) || truthy(kv["Terminal"]) {
		return App{}, false
	}
	name := kv["Name"]
	if name == "" {
		return App{}, false
	}
	binary, keyword := execKeyword(kv["Exec"])
	if keyword == "" {
		return App{}, false
	}
	var cats []string
	if kv["Categories"] != "" {
		for _, c := range strings.Split(kv["Categories"], ";") {
			if c = strings.TrimSpace(c); c != "" {
				cats = append(cats, c)
			}
		}
	}
	return App{
		Name: name, Comment: kv["Comment"], Exec: kv["Exec"], Binary: binary,
		Keyword: keyword, Categories: cats, Icon: kv["Icon"], Path: path,
	}, true
}

func truthy(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "true") }

// execKeyword resolves the Exec line to a binary basename and a match keyword.
func execKeyword(exec string) (binary, keyword string) {
	if exec == "" {
		return "", ""
	}
	toks := tokenize(exec)
	// drop field codes and leading wrappers
	wrappers := map[string]bool{"env": true, "sh": true, "bash": true, "setsid": true, "nohup": true, "dbus-launch": true, "gtk-launch": true}
	i := 0
	for i < len(toks) {
		t := toks[i]
		if strings.HasPrefix(t, "%") || strings.Contains(t, "=") {
			i++
			continue
		}
		b := strings.ToLower(filepath.Base(t))
		// flatpak / snap wrappers: use the app id's last segment
		if b == "flatpak" || b == "snap" {
			for j := i + 1; j < len(toks); j++ {
				a := toks[j]
				if a == "run" || strings.HasPrefix(a, "-") || strings.HasPrefix(a, "%") {
					continue
				}
				segs := strings.Split(a, ".")
				generic := map[string]bool{"desktop": true, "client": true, "app": true, "gui": true, "bin": true, "stable": true, "free": true, "linux": true}
				for len(segs) > 1 && generic[strings.ToLower(segs[len(segs)-1])] {
					segs = segs[:len(segs)-1]
				}
				id := strings.ToLower(segs[len(segs)-1])
				return id, stem(id)
			}
			i++
			continue
		}
		if wrappers[b] {
			i++
			continue
		}
		return b, stem(b)
	}
	return "", ""
}

func stem(base string) string {
	base = strings.ToLower(base)
	if a, ok := stemAlias[base]; ok {
		return a
	}
	for _, suf := range []string{"-stable", "-beta", "-bin", "-git", "-nightly"} {
		if strings.HasSuffix(base, suf) {
			s := strings.TrimSuffix(base, suf)
			if a, ok := stemAlias[s]; ok {
				return a
			}
			return s
		}
	}
	return base
}

// tokenize splits an Exec string on spaces, honouring simple quoting.
func tokenize(s string) []string {
	var toks []string
	var cur strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ' ' || r == '\t':
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	return toks
}
