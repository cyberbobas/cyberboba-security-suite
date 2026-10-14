// Package geo resolves IP addresses (or hostnames) to a country/city using an
// external HTTP provider, caching results in memory. Lookups are non-blocking:
// a cache miss returns immediately and triggers a background fetch, so callers
// (the topology endpoint) never stall on the network.
package geo

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Info is a resolved location.
type Info struct {
	IP      string  `json:"ip,omitempty"`
	Country string  `json:"country,omitempty"`
	CC      string  `json:"cc,omitempty"` // ISO-3166 alpha-2
	City    string  `json:"city,omitempty"`
	ISP     string  `json:"isp,omitempty"`
	Flag    string  `json:"flag,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
	Private bool    `json:"private,omitempty"`
}

type entry struct {
	info Info
	at   time.Time
	err  bool
}

// Cache is a concurrency-safe geolocation cache.
type Cache struct {
	mu       sync.Mutex
	m        map[string]*entry
	inflight map[string]bool
	provider string
	ttl      time.Duration
	enabled  bool
	client   *http.Client
	logf     func(string, ...interface{})
}

// New builds a cache. client should dial directly (the daemon's own traffic is
// already marked to bypass interception). A nil client uses a default one.
func New(enabled bool, provider string, ttlHours int, client *http.Client, logf func(string, ...interface{})) *Cache {
	if client == nil {
		client = &http.Client{Timeout: 6 * time.Second}
	}
	if ttlHours <= 0 {
		ttlHours = 24
	}
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &Cache{
		m:        map[string]*entry{},
		inflight: map[string]bool{},
		provider: provider,
		ttl:      time.Duration(ttlHours) * time.Hour,
		enabled:  enabled && provider != "",
		client:   client,
		logf:     logf,
	}
}

// Enabled reports whether lookups will be attempted.
func (c *Cache) Enabled() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// Configure updates provider/enabled at runtime (config reload).
func (c *Cache) Configure(enabled bool, provider string, ttlHours int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled && provider != ""
	c.provider = provider
	if ttlHours > 0 {
		c.ttl = time.Duration(ttlHours) * time.Hour
	}
}

// Flag turns an ISO-3166 alpha-2 country code into a regional-indicator emoji.
func Flag(cc string) string {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return ""
	}
	r := []rune{0x1F1E6 + rune(cc[0]-'A'), 0x1F1E6 + rune(cc[1]-'A')}
	return string(r)
}

func privateInfo(ip string) (Info, bool) {
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}
	a := net.ParseIP(host)
	if a == nil {
		return Info{}, false
	}
	if a.IsLoopback() {
		return Info{IP: host, Country: "Localhost", Private: true}, true
	}
	if a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return Info{IP: host, Country: "Local Network", Private: true}, true
	}
	return Info{}, false
}

// Lookup returns a cached result immediately. found is false on a cache miss,
// in which case a background fetch is started (if enabled) for next time.
func (c *Cache) Lookup(addr string) (Info, bool) {
	if c == nil || addr == "" {
		return Info{}, false
	}
	key := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		key = h
	}
	if info, ok := privateInfo(key); ok {
		return info, true
	}
	now := time.Now()
	c.mu.Lock()
	e, ok := c.m[key]
	fresh := ok && now.Sub(e.at) < c.ttl
	enabled := c.enabled
	if fresh {
		info := e.info
		err := e.err
		c.mu.Unlock()
		return info, !err
	}
	if !enabled {
		c.mu.Unlock()
		return Info{}, false
	}
	if !c.inflight[key] {
		c.inflight[key] = true
		go c.fetch(key)
	}
	if ok && !e.err { // serve stale while refreshing
		info := e.info
		c.mu.Unlock()
		return info, true
	}
	c.mu.Unlock()
	return Info{}, false
}

// LookupNow performs a synchronous lookup (used by the CLI/MCP single-shot).
func (c *Cache) LookupNow(addr string) (Info, error) {
	if info, ok := privateInfo(addr); ok {
		return info, nil
	}
	key := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		key = h
	}
	c.mu.Lock()
	e, ok := c.m[key]
	if ok && time.Since(e.at) < c.ttl && !e.err {
		info := e.info
		c.mu.Unlock()
		return info, nil
	}
	c.mu.Unlock()
	info := c.do(key)
	c.mu.Lock()
	c.m[key] = &entry{info: info, at: time.Now(), err: info.Country == ""}
	c.mu.Unlock()
	return info, nil
}

func (c *Cache) fetch(key string) {
	info := c.do(key)
	c.mu.Lock()
	c.m[key] = &entry{info: info, at: time.Now(), err: info.Country == ""}
	delete(c.inflight, key)
	c.mu.Unlock()
}

// providerResp matches the common ip-api.com / ipwho.is field shape.
type providerResp struct {
	Status       string  `json:"status"`
	Message      string  `json:"message"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"countryCode"`
	CountryCode2 string  `json:"country_code"`
	CountryName  string  `json:"country_name"`
	City         string  `json:"city"`
	ISP          string  `json:"isp"`
	Org          string  `json:"org"`
	Query        string  `json:"query"`
	IP           string  `json:"ip"`
	Lat          float64 `json:"lat"`
	Lon          float64 `json:"lon"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
}

func (c *Cache) do(key string) Info {
	c.mu.Lock()
	provider, enabled, client := c.provider, c.enabled, c.client
	c.mu.Unlock()
	if !enabled {
		return Info{}
	}
	ipForURL := key
	if key == selfKey {
		ipForURL = ""
	}
	url := strings.ReplaceAll(provider, "{ip}", ipForURL)
	// ip-api style field lists: make sure coordinates are included so the map
	// can plot real positions (harmless for providers that ignore it).
	if strings.Contains(url, "fields=") && !strings.Contains(url, "lat") {
		url += ",lat,lon"
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return Info{}
	}
	req.Header.Set("User-Agent", "cyberboba/geo")
	resp, err := client.Do(req)
	if err != nil {
		c.logf("geo lookup %s: %v", key, err)
		return Info{}
	}
	defer resp.Body.Close()
	var pr providerResp
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return Info{}
	}
	if pr.Status == "fail" {
		return Info{}
	}
	cc := pr.CountryCode
	if cc == "" {
		cc = pr.CountryCode2
	}
	country := pr.Country
	if country == "" {
		country = pr.CountryName
	}
	isp := pr.ISP
	if isp == "" {
		isp = pr.Org
	}
	ip := pr.Query
	if ip == "" {
		ip = pr.IP
	}
	if ip == "" {
		ip = key
	}
	lat, lon := pr.Lat, pr.Lon
	if lat == 0 && lon == 0 {
		lat, lon = pr.Latitude, pr.Longitude
	}
	return Info{IP: ip, Country: country, CC: cc, City: pr.City, ISP: isp, Flag: Flag(cc), Lat: lat, Lon: lon}
}

// selfKey is the cache key under which the daemon's own public-IP geolocation
// is stored (the "home" point on the live map). The provider is queried with
// an empty address, which ip-api.com-style services resolve to the caller.
const selfKey = "\x00self"

// Self returns the cached geolocation of this machine's own public IP, kicking
// off a background lookup on a miss (like Lookup). Used to place "home" on the
// map.
func (c *Cache) Self() (Info, bool) {
	if c == nil {
		return Info{}, false
	}
	now := time.Now()
	c.mu.Lock()
	e, ok := c.m[selfKey]
	fresh := ok && now.Sub(e.at) < c.ttl
	enabled := c.enabled
	if fresh && !e.err {
		info := e.info
		c.mu.Unlock()
		return info, true
	}
	if enabled && !c.inflight[selfKey] {
		c.inflight[selfKey] = true
		go c.fetch(selfKey)
	}
	if ok && !e.err {
		info := e.info
		c.mu.Unlock()
		return info, true
	}
	c.mu.Unlock()
	return Info{}, false
}
