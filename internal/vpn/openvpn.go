package vpn

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"cyberboba/internal/config"
)

// openvpn runs an OpenVPN client process and talks to its management
// interface for state and byte counters.
type openvpn struct {
	m    *Manager
	t    *tunnel
	log  ringLog
	mu   sync.Mutex
	cmd  *exec.Cmd
	mgmt net.Conn
	done chan struct{}
	rx   int64
	tx   int64
	dev  string
	gw   string
}

var (
	tunRe = regexp.MustCompile(`TUN/TAP device (\S+) opened`)
	gwRe  = regexp.MustCompile(`route_vpn_gateway\s*=\s*(\S+)|ifconfig_remote\s*=\s*(\S+)`)
)

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func (o *openvpn) Up() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.cmd != nil {
		return errors.New("already running")
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	p := o.t.profile
	cfgPath, err := filepath.Abs(p.Config)
	if err != nil {
		return err
	}
	args := []string{
		"--config", cfgPath,
		"--management", "127.0.0.1", strconv.Itoa(port),
		"--management-hold",
		"--management-log-cache", "200",
		"--verb", "3",
		"--script-security", "2",
	}
	if p.Interface != "" {
		args = append(args, "--dev", InterfaceName(p), "--dev-type", "tun")
	}
	if af, err := o.m.authFile(p); err != nil {
		return err
	} else if af != "" {
		args = append(args, "--auth-user-pass", af)
	}
	if p.Mode == config.VPNModeSelective {
		// Do not touch the main routing table; cyberboba installs its own.
		args = append(args, "--route-noexec", "--pull-filter", "ignore", "redirect-gateway",
			"--pull-filter", "ignore", "dhcp-option")
	}
	args = append(args, p.ExtraArgs...)
	cmd := exec.Command("openvpn", args...)
	cmd.Dir = filepath.Dir(cfgPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("openvpn: %w", err)
	}
	o.cmd = cmd
	o.done = make(chan struct{})
	o.rx, o.tx, o.dev, o.gw = 0, 0, "", ""
	o.t.mu.Lock()
	o.t.status.PID = cmd.Process.Pid
	o.t.mu.Unlock()
	o.log.add(fmt.Sprintf("started openvpn pid %d: %s", cmd.Process.Pid, strings.Join(args, " ")))

	go o.readOutput(stdout)
	go o.wait(cmd)
	go o.manage(port)
	return nil
}

func (o *openvpn) readOutput(r interface{ Read([]byte) (int, error) }) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		o.log.add(line)
		if m := tunRe.FindStringSubmatch(line); m != nil {
			o.mu.Lock()
			o.dev = m[1]
			o.mu.Unlock()
		}
		if m := gwRe.FindStringSubmatch(line); m != nil {
			o.mu.Lock()
			if m[1] != "" {
				o.gw = m[1]
			} else if o.gw == "" {
				o.gw = m[2]
			}
			o.mu.Unlock()
		}
	}
}

func (o *openvpn) wait(cmd *exec.Cmd) {
	err := cmd.Wait()
	o.mu.Lock()
	if o.cmd == cmd {
		o.cmd = nil
		if o.mgmt != nil {
			o.mgmt.Close()
			o.mgmt = nil
		}
		close(o.done)
	}
	o.mu.Unlock()
	o.m.unroute(o.t)
	o.t.mu.Lock()
	wasUp := o.t.status.State == StateUp || o.t.status.State == StateConnecting
	o.t.status.PID = 0
	o.t.mu.Unlock()
	if wasUp {
		if err != nil {
			o.log.add("openvpn exited: " + err.Error())
			e := fmt.Errorf("openvpn exited: %v (%s)", err, lastLine(strings.Join(o.log.get(), "\n")))
			o.m.markError(o.t, e)
			o.m.lost(o.t, e)
		} else {
			o.t.mu.Lock()
			o.t.status.State = StateDown
			o.t.status.Since = nil
			o.t.mu.Unlock()
			o.m.publish(o.t.snapshot())
		}
	}
}

// manage connects to the management socket, releases the hold and follows
// state / bytecount notifications.
func (o *openvpn) manage(port int) {
	var conn net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			break
		}
		select {
		case <-o.done:
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	if err != nil {
		o.m.markError(o.t, fmt.Errorf("management interface: %v", err))
		o.kill()
		return
	}
	o.mu.Lock()
	o.mgmt = conn
	o.mu.Unlock()
	w := func(s string) { fmt.Fprintf(conn, "%s\r\n", s) }
	w("state on")
	w("bytecount 2")
	w("hold release")
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, ">BYTECOUNT:"):
			f := strings.Split(strings.TrimPrefix(line, ">BYTECOUNT:"), ",")
			if len(f) == 2 {
				rx, _ := strconv.ParseInt(f[0], 10, 64)
				tx, _ := strconv.ParseInt(f[1], 10, 64)
				o.mu.Lock()
				o.rx, o.tx = rx, tx
				o.mu.Unlock()
			}
		case strings.HasPrefix(line, ">STATE:"):
			f := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
			if len(f) >= 2 {
				o.onState(f)
			}
		case strings.HasPrefix(line, ">PASSWORD:"):
			o.log.add(line)
			if strings.Contains(line, "Need") {
				o.m.markError(o.t, errors.New("openvpn asks for credentials; set auth_file in the profile"))
				o.kill()
				return
			}
		case strings.HasPrefix(line, ">FATAL:") || strings.HasPrefix(line, ">LOG:"):
			o.log.add(line)
		}
	}
}

func (o *openvpn) onState(f []string) {
	state := f[1]
	o.log.add("state: " + strings.Join(f, ","))
	switch state {
	case "CONNECTED":
		localIP := ""
		remote := ""
		if len(f) > 3 {
			localIP = f[3]
		}
		if len(f) > 4 {
			remote = f[4]
			if len(f) > 5 && f[5] != "" {
				remote += ":" + f[5]
			}
		}
		// wait briefly for the device name from the log
		var dev, gw string
		for i := 0; i < 20; i++ {
			o.mu.Lock()
			dev, gw = o.dev, o.gw
			o.mu.Unlock()
			if dev != "" {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if dev == "" {
			dev = InterfaceName(o.t.profile)
		}
		if o.t.profile.Mode == config.VPNModeSelective {
			// With topology subnet the tun device is a plain link; a gateway
			// is only needed for net30 where the remote end is the peer.
			if err := o.m.route(o.t, dev, gw, ""); err != nil {
				o.log.add("routing failed: " + err.Error())
				o.m.markError(o.t, fmt.Errorf("routing: %w", err))
				o.kill()
				return
			}
		} else {
			_ = o.m.route(o.t, dev, "", "")
		}
		o.t.mu.Lock()
		o.t.status.LocalIP = localIP
		o.t.status.Endpoint = remote
		o.t.endpoint = remote
		o.t.mu.Unlock()
		o.m.markUp(o.t, dev)
		o.m.logf("info", "vpn %s: openvpn connected on %s (%s)", o.t.profile.Name, dev, localIP)
	case "RECONNECTING", "EXITING":
		o.m.unroute(o.t)
		o.t.mu.Lock()
		wasUp := o.t.status.State == StateUp
		if wasUp {
			o.t.status.State = StateConnecting
		}
		o.t.mu.Unlock()
		o.m.publish(o.t.snapshot())
		if wasUp && o.t.profile.KillSwitch {
			o.m.killSwitch(o.t, true)
		}
	}
}

func (o *openvpn) kill() {
	o.mu.Lock()
	cmd := o.cmd
	o.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
}

func (o *openvpn) Down() error {
	o.mu.Lock()
	cmd := o.cmd
	done := o.done
	mg := o.mgmt
	o.mu.Unlock()
	if cmd == nil {
		return nil
	}
	if mg != nil {
		fmt.Fprintf(mg, "signal SIGTERM\r\n")
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	o.m.logf("info", "vpn %s: openvpn stopped", o.t.profile.Name)
	return nil
}

func (o *openvpn) Refresh(s *Status) {
	o.mu.Lock()
	s.RxBytes, s.TxBytes = o.rx, o.tx
	if o.cmd != nil && o.cmd.Process != nil {
		s.PID = o.cmd.Process.Pid
	}
	o.mu.Unlock()
	if s.State == StateUp && s.Interface != "" {
		if rx, tx := ifaceCounters(s.Interface); rx > 0 || tx > 0 {
			s.RxBytes, s.TxBytes = rx, tx
		}
		if s.LocalIP == "" {
			s.LocalIP = localIPv4(s.Interface)
		}
	}
}

func (o *openvpn) Log() []string { return o.log.get() }

// ensure the helper used in the config template path is referenced
var _ = os.Getpid
