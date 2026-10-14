// Package sysstat samples host-level resource usage for the Processes page
// header: overall and per-core CPU load, memory/swap, and every temperature
// (and fan) sensor the kernel exposes under /sys. CPU% is computed as a delta
// between successive calls, so callers should poll on an interval.
package sysstat

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPU is overall and per-core utilisation plus load averages.
type CPU struct {
	Pct     float64   `json:"pct"`
	PerCore []float64 `json:"per_core"`
	Load1   float64   `json:"load1"`
	Load5   float64   `json:"load5"`
	Load15  float64   `json:"load15"`
	NCPU    int       `json:"ncpu"`
}

// Mem is memory and swap usage in kilobytes.
type Mem struct {
	TotalKB   int64   `json:"total_kb"`
	UsedKB    int64   `json:"used_kb"`
	FreeKB    int64   `json:"free_kb"`
	AvailKB   int64   `json:"avail_kb"`
	CachedKB  int64   `json:"cached_kb"`
	BuffersKB int64   `json:"buffers_kb"`
	Pct       float64 `json:"pct"`
	SwapKB    int64   `json:"swap_total_kb"`
	SwapUsed  int64   `json:"swap_used_kb"`
	SwapPct   float64 `json:"swap_pct"`
}

// Temp is one temperature sensor reading.
type Temp struct {
	Chip    string  `json:"chip"`
	Label   string  `json:"label"`
	Celsius float64 `json:"celsius"`
}

// Fan is one fan speed reading.
type Fan struct {
	Chip  string `json:"chip"`
	Label string `json:"label"`
	RPM   int    `json:"rpm"`
}

// Stat is a full snapshot.
type Stat struct {
	CPU   CPU       `json:"cpu"`
	Mem   Mem       `json:"mem"`
	Temps []Temp    `json:"temps"`
	Fans  []Fan     `json:"fans,omitempty"`
	At    time.Time `json:"at"`
}

type cpuTimes struct{ total, idle uint64 }

// Monitor keeps the previous /proc/stat sample so CPU% is a delta.
type Monitor struct {
	mu   sync.Mutex
	prev map[string]cpuTimes
}

// New builds a monitor.
func New() *Monitor { return &Monitor{prev: map[string]cpuTimes{}} }

// Sample returns a fresh snapshot.
func (m *Monitor) Sample() Stat {
	s := Stat{At: time.Now()}
	s.CPU = m.cpu()
	s.Mem = mem()
	s.Temps, s.Fans = sensors()
	return s
}

func (m *Monitor) cpu() CPU {
	c := CPU{}
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return c
	}
	m.mu.Lock()
	cur := map[string]cpuTimes{}
	var cores []struct {
		idx int
		pct float64
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		key := f[0]
		var total, idle uint64
		for i := 1; i < len(f); i++ {
			v, _ := strconv.ParseUint(f[i], 10, 64)
			total += v
			if i == 4 || i == 5 { // idle + iowait
				idle += v
			}
		}
		cur[key] = cpuTimes{total: total, idle: idle}
		if prev, ok := m.prev[key]; ok {
			dt := float64(total - prev.total)
			di := float64(idle - prev.idle)
			pct := 0.0
			if dt > 0 {
				pct = (dt - di) / dt * 100.0
			}
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}
			if key == "cpu" {
				c.Pct = round1(pct)
			} else if strings.HasPrefix(key, "cpu") {
				idx, _ := strconv.Atoi(key[3:])
				cores = append(cores, struct {
					idx int
					pct float64
				}{idx, round1(pct)})
			}
		}
	}
	m.prev = cur
	m.mu.Unlock()

	sort.Slice(cores, func(i, j int) bool { return cores[i].idx < cores[j].idx })
	for _, cc := range cores {
		c.PerCore = append(c.PerCore, cc.pct)
	}
	c.NCPU = len(cores)
	if c.NCPU == 0 {
		c.NCPU = len(c.PerCore)
	}

	if la, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(la))
		if len(f) >= 3 {
			c.Load1, _ = strconv.ParseFloat(f[0], 64)
			c.Load5, _ = strconv.ParseFloat(f[1], 64)
			c.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	return c
}

func mem() Mem {
	m := Mem{}
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return m
	}
	get := map[string]int64{}
	for _, line := range strings.Split(string(b), "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		v, _ := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[i+1:]), "kB")), 10, 64)
		get[line[:i]] = v
	}
	m.TotalKB = get["MemTotal"]
	m.FreeKB = get["MemFree"]
	m.AvailKB = get["MemAvailable"]
	m.CachedKB = get["Cached"]
	m.BuffersKB = get["Buffers"]
	if m.AvailKB == 0 { // very old kernels
		m.AvailKB = m.FreeKB + m.CachedKB + m.BuffersKB
	}
	m.UsedKB = m.TotalKB - m.AvailKB
	if m.TotalKB > 0 {
		m.Pct = round1(float64(m.UsedKB) / float64(m.TotalKB) * 100.0)
	}
	m.SwapKB = get["SwapTotal"]
	m.SwapUsed = get["SwapTotal"] - get["SwapFree"]
	if m.SwapKB > 0 {
		m.SwapPct = round1(float64(m.SwapUsed) / float64(m.SwapKB) * 100.0)
	}
	return m
}

// sensors reads every temperature and fan under /sys/class/hwmon plus any
// thermal zone not already covered by a hwmon chip.
func sensors() ([]Temp, []Fan) {
	var temps []Temp
	var fans []Fan
	chipSeen := map[string]bool{}

	hwmons, _ := filepath.Glob("/sys/class/hwmon/hwmon*")
	for _, hw := range hwmons {
		chip := readStr(filepath.Join(hw, "name"))
		if chip == "" {
			chip = filepath.Base(hw)
		}
		chipSeen[chip] = true
		// temperatures
		tins, _ := filepath.Glob(filepath.Join(hw, "temp*_input"))
		sort.Strings(tins)
		for _, ti := range tins {
			mv := readInt(ti)
			if mv == 0 {
				continue
			}
			label := readStr(strings.TrimSuffix(ti, "_input") + "_label")
			temps = append(temps, Temp{Chip: chip, Label: label, Celsius: round1(float64(mv) / 1000.0)})
		}
		// fans
		fins, _ := filepath.Glob(filepath.Join(hw, "fan*_input"))
		sort.Strings(fins)
		for _, fi := range fins {
			rpm := int(readInt(fi))
			if rpm <= 0 {
				continue
			}
			label := readStr(strings.TrimSuffix(fi, "_input") + "_label")
			fans = append(fans, Fan{Chip: chip, Label: label, RPM: rpm})
		}
	}

	// thermal zones not represented by a hwmon chip (skip control/duplicate ones)
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*")
	for _, z := range zones {
		typ := readStr(filepath.Join(z, "type"))
		if typ == "" || chipSeen[typ] {
			continue
		}
		lt := strings.ToLower(typ)
		// drop CPU-package duplicates (coretemp already reports it) and ACPI
		// control zones that don't report a real temperature (INT3400 etc.).
		if strings.Contains(lt, "pkg") || strings.HasPrefix(typ, "INT3400") {
			continue
		}
		mv := readInt(filepath.Join(z, "temp"))
		if mv <= 0 {
			continue
		}
		c := round1(float64(mv) / 1000.0)
		if c < 1 || c > 150 { // implausible control-zone readings
			continue
		}
		temps = append(temps, Temp{Chip: typ, Celsius: c})
	}
	return temps, fans
}

func readStr(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readInt(p string) int64 {
	v, _ := strconv.ParseInt(readStr(p), 10, 64)
	return v
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
