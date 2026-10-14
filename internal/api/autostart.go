package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// unitName is the systemd unit that runs the cyberboba daemon on boot.
const unitName = "cyberboba.service"

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (s *Server) autostartRoutes() {
	m := s.mux

	// GET /api/system/autostart — whether the daemon is set to start on boot
	// (systemd "enabled"), whether it is running now, and which VPNs are
	// flagged to auto-connect when it starts.
	m.HandleFunc("GET /api/system/autostart", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.autostartState())
	})

	// POST /api/system/autostart {enabled:bool} — enable/disable starting the
	// daemon on system boot via systemctl (requires running as root).
	m.HandleFunc("POST /api/system/autostart", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Enabled *bool `json:"enabled"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if in.Enabled == nil {
			writeErr(w, 400, errors.New("enabled is required"))
			return
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			writeErr(w, 501, errors.New("systemctl not available on this system"))
			return
		}
		if os.Geteuid() != 0 {
			writeErr(w, 403, errors.New("the daemon must run as root to change boot autostart"))
			return
		}
		verb := "disable"
		if *in.Enabled {
			verb = "enable"
		}
		if out, err := systemctl(verb, unitName); err != nil {
			writeErr(w, 500, fmt.Errorf("systemctl %s %s: %v: %s", verb, unitName, err, out))
			return
		}
		writeJSON(w, s.autostartState())
	})
}

func (s *Server) autostartState() map[string]interface{} {
	_, sctlErr := exec.LookPath("systemctl")
	enabledRaw, _ := systemctl("is-enabled", unitName) // "enabled"/"disabled"/"static"/...
	activeRaw, _ := systemctl("is-active", unitName)
	unitKnown := enabledRaw == "enabled" || enabledRaw == "disabled" || enabledRaw == "static" || enabledRaw == "masked"

	var vpns []string
	for _, v := range s.d.Store.Get().VPNs {
		if v.Autostart {
			vpns = append(vpns, v.Name)
		}
	}
	if vpns == nil {
		vpns = []string{}
	}
	return map[string]interface{}{
		"service_enabled": enabledRaw == "enabled",
		"service_active":  activeRaw == "active",
		"is_enabled_raw":  enabledRaw,
		"vpn_autostart":   vpns,
		"unit":            unitName,
		"can_manage":      sctlErr == nil && os.Geteuid() == 0 && unitKnown,
	}
}
