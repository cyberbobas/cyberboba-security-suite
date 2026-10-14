package topology

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"cyberboba/internal/rules"
	"cyberboba/internal/stats"
)

// MapPoint is one plotted location on the live map: either "home", or one
// (application -> destination host) pair aggregating that app's current
// connections to that host, so the map is application-centric.
type MapPoint struct {
	ID       string  `json:"id"`
	Kind     string  `json:"kind"` // home | dest
	Label    string  `json:"label"`
	Host     string  `json:"host,omitempty"`
	IP       string  `json:"ip,omitempty"`
	Country  string  `json:"country,omitempty"`
	CC       string  `json:"cc,omitempty"`
	City     string  `json:"city,omitempty"`
	ISP      string  `json:"isp,omitempty"`
	Flag     string  `json:"flag,omitempty"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Approx   bool    `json:"approx,omitempty"` // lat/lon from country centroid, not precise
	Located  bool    `json:"located"`          // has usable coordinates
	Conns    int     `json:"conns,omitempty"`
	BytesIn  int64   `json:"bytes_in,omitempty"`
	BytesOut int64   `json:"bytes_out,omitempty"`
	App      string  `json:"app,omitempty"` // the application this point belongs to
	Action   string  `json:"action,omitempty"`
	Blocked  bool    `json:"blocked,omitempty"`
}

// MapView is the data behind the live geographic map tab.
type MapView struct {
	GeoEnabled   bool       `json:"geo_enabled"`
	Home         *MapPoint  `json:"home,omitempty"`
	Points       []MapPoint `json:"points"`
	BlockedHosts []string   `json:"blocked_hosts,omitempty"`
	GeneratedAt  time.Time  `json:"generated_at"`
}

// BuildMap aggregates live connections into geolocated destination points.
// blocked is the firewall's host blocklist, used to flag points already denied
// (so the UI can show/undo them).
func (b *Builder) BuildMap(conns []stats.Conn, blocked []string) MapView {
	mv := MapView{GeneratedAt: time.Now(), BlockedHosts: blocked, GeoEnabled: b.Geo.Enabled()}

	if b.Geo != nil {
		if info, ok := b.Geo.Self(); ok {
			hp := &MapPoint{ID: "home", Kind: "home", Label: "this machine",
				Country: info.Country, CC: info.CC, City: info.City, ISP: info.ISP, Flag: info.Flag,
				IP: info.IP, Lat: info.Lat, Lon: info.Lon}
			locate(hp, info.Lat, info.Lon, info.CC)
			mv.Home = hp
		}
	}

	// Cache geo per destination so repeated (app,host) pairs reuse one lookup.
	type geoInfo struct {
		country, cc, city, isp, flag string
		lat, lon                     float64
		located, approx              bool
	}
	geoCache := map[string]geoInfo{}
	destGeo := func(host, dstIP string, ip netip.Addr) geoInfo {
		key := dstIP
		if key == "" {
			key = host
		}
		if g, ok := geoCache[key]; ok {
			return g
		}
		var g geoInfo
		if b.Geo != nil {
			info, got := b.Geo.Lookup(dstIP)
			if !got && host != "" {
				info, got = b.Geo.Lookup(host)
			}
			if got {
				g.country, g.cc, g.city, g.isp, g.flag = info.Country, info.CC, info.City, info.ISP, info.Flag
				tmp := &MapPoint{}
				locate(tmp, info.Lat, info.Lon, info.CC)
				g.lat, g.lon, g.located, g.approx = tmp.Lat, tmp.Lon, tmp.Located, tmp.Approx
			}
		}
		geoCache[key] = g
		return g
	}

	byKey := map[string]*MapPoint{}
	order := []string{}

	for i := range conns {
		c := &conns[i]
		if c.State != stats.StateOpen && c.State != stats.StateBlocked {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(c.Host, "."))
		var ip netip.Addr
		if c.DstIP != "" {
			ip, _ = netip.ParseAddr(c.DstIP)
		}
		// skip purely-local destinations (no country to plot)
		if ip.IsValid() && (ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			continue
		}
		dest := host
		if dest == "" {
			dest = c.DstIP
		}
		if dest == "" {
			continue
		}
		app := c.App
		if app == "" {
			app = "?"
		}
		key := app + "\x00" + dest
		p, ok := byKey[key]
		if !ok {
			p = &MapPoint{ID: key, Kind: "dest", App: app, Host: c.Host, IP: c.DstIP, Action: c.Action}
			p.Label = c.Host
			if p.Label == "" {
				p.Label = c.DstIP
			}
			g := destGeo(host, c.DstIP, ip)
			p.Country, p.CC, p.City, p.ISP, p.Flag = g.country, g.cc, g.city, g.isp, g.flag
			p.Lat, p.Lon, p.Located, p.Approx = g.lat, g.lon, g.located, g.approx
			p.Blocked = matchBlocked(blocked, host, ip)
			byKey[key] = p
			order = append(order, key)
		}
		p.Conns++
		p.BytesIn += c.BytesIn
		p.BytesOut += c.BytesOut
		if c.State == stats.StateBlocked {
			p.Action = "block"
		}
	}

	for _, key := range order {
		mv.Points = append(mv.Points, *byKey[key])
	}
	// busiest first
	sort.SliceStable(mv.Points, func(i, j int) bool {
		bi := mv.Points[i].BytesIn + mv.Points[i].BytesOut
		bj := mv.Points[j].BytesIn + mv.Points[j].BytesOut
		if bi != bj {
			return bi > bj
		}
		return mv.Points[i].Conns > mv.Points[j].Conns
	})
	return mv
}

func locate(p *MapPoint, lat, lon float64, cc string) {
	if lat != 0 || lon != 0 {
		p.Lat, p.Lon, p.Located, p.Approx = lat, lon, true, false
		return
	}
	if ll, ok := centroid[strings.ToUpper(cc)]; ok {
		p.Lat, p.Lon, p.Located, p.Approx = ll[0], ll[1], true, true
	}
}

func matchBlocked(blocked []string, host string, ip netip.Addr) bool {
	for _, pat := range blocked {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(pat); err == nil {
			if ip.IsValid() && pfx.Contains(ip.Unmap()) {
				return true
			}
			continue
		}
		if a, err := netip.ParseAddr(pat); err == nil {
			if ip.IsValid() && a == ip.Unmap() {
				return true
			}
			continue
		}
		if host != "" && rules.MatchHost(strings.ToLower(pat), host) {
			return true
		}
	}
	return false
}
