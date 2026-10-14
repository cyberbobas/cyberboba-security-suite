package apps

import "testing"

func TestExecKeyword(t *testing.T) {
	cases := []struct{ exec, wantBin, wantKw string }{
		{"firefox %u", "firefox", "firefox"},
		{"/usr/bin/google-chrome-stable %U", "google-chrome-stable", "chrome"},
		{"env GTK=1 /usr/bin/code --unity-launch %F", "code", "code"},
		{"flatpak run org.telegram.desktop", "telegram", "telegram"},
		{"flatpak run --branch=stable org.mozilla.firefox @@u %U @@", "firefox", "firefox"},
		{"brave-browser-stable %U", "brave-browser-stable", "brave"},
	}
	for _, c := range cases {
		b, kw := execKeyword(c.exec)
		if b != c.wantBin || kw != c.wantKw {
			t.Errorf("execKeyword(%q) = (%q,%q), want (%q,%q)", c.exec, b, kw, c.wantBin, c.wantKw)
		}
	}
}

func TestListRuns(t *testing.T) {
	if l := List(); l == nil {
		t.Skip("no desktop files on this host")
	}
}
