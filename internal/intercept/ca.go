package intercept

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CA is the local certificate authority used to mint per-host leaf
// certificates for TLS interception.
type CA struct {
	Dir     string
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
	mu      sync.Mutex
	leafs   map[string]*tls.Certificate
}

// LoadOrCreateCA reads ca.crt/ca.key from dir or generates a new pair.
func LoadOrCreateCA(dir string) (*CA, error) {
	ca := &CA{Dir: dir, leafs: map[string]*tls.Certificate{}}
	if err := ca.load(); err == nil {
		return ca, nil
	}
	if err := ca.generate(); err != nil {
		return nil, err
	}
	return ca, nil
}

func (ca *CA) load() error {
	certPEM, err := os.ReadFile(filepath.Join(ca.Dir, "ca.crt"))
	if err != nil {
		return err
	}
	_ = os.Chmod(ca.Dir, 0o755)
	_ = os.Chmod(filepath.Join(ca.Dir, "ca.crt"), 0o644)
	keyPEM, err := os.ReadFile(filepath.Join(ca.Dir, "ca.key"))
	if err != nil {
		return err
	}
	tc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		return err
	}
	signer, ok := tc.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("ca.key: unsupported key type")
	}
	ca.cert, ca.key, ca.certPEM = cert, signer, certPEM
	return nil
}

func (ca *CA) generate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "cyberboba intercept CA", Organization: []string{"cyberboba"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	// The directory and certificate must be world-readable so that clients
	// (curl --cacert, browsers) can use the CA; only the key is private.
	if err := os.MkdirAll(ca.Dir, 0o755); err != nil {
		return err
	}
	_ = os.Chmod(ca.Dir, 0o755)
	if err := os.WriteFile(filepath.Join(ca.Dir, "ca.key"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(ca.Dir, "ca.crt"), certPEM, 0o644); err != nil {
		return err
	}
	ca.mu.Lock()
	ca.cert, ca.key, ca.certPEM = cert, key, certPEM
	ca.leafs = map[string]*tls.Certificate{}
	ca.mu.Unlock()
	return nil
}

// Regenerate replaces the CA (all leaf certificates are invalidated).
func (ca *CA) Regenerate() error {
	_ = os.Remove(filepath.Join(ca.Dir, "ca.crt"))
	_ = os.Remove(filepath.Join(ca.Dir, "ca.key"))
	return ca.generate()
}

// PEM returns the CA certificate.
func (ca *CA) PEM() []byte {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.certPEM
}

// CertPath is the on-disk certificate path.
func (ca *CA) CertPath() string { return filepath.Join(ca.Dir, "ca.crt") }

// Fingerprint returns the SHA-256 fingerprint of the CA certificate.
func (ca *CA) Fingerprint() string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.cert == nil {
		return ""
	}
	sum := sha256.Sum256(ca.cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return "SHA256:" + strings.Join(parts, ":")
}

// NotAfter returns the CA expiry.
func (ca *CA) NotAfter() time.Time {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.cert == nil {
		return time.Time{}
	}
	return ca.cert.NotAfter
}

// Leaf returns (and caches) a certificate for host (DNS name or IP).
func (ca *CA) Leaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		host = "localhost"
	}
	ca.mu.Lock()
	if c, ok := ca.leafs[host]; ok && time.Now().Before(c.Leaf.NotAfter.Add(-24*time.Hour)) {
		ca.mu.Unlock()
		return c, nil
	}
	ca.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"cyberboba intercept"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 397),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
		// also cover a wildcard sibling so www.x and x share nothing but
		// subdomains of x get their own cert; keep it simple: one name.
	}
	ca.mu.Lock()
	caCert, caKey := ca.cert, ca.key
	ca.mu.Unlock()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
	}
	leaf, _ := x509.ParseCertificate(der)
	c := &tls.Certificate{Certificate: [][]byte{der, caCert.Raw}, PrivateKey: key, Leaf: leaf}
	ca.mu.Lock()
	if len(ca.leafs) > 2000 {
		ca.leafs = map[string]*tls.Certificate{}
	}
	ca.leafs[host] = c
	ca.mu.Unlock()
	return c, nil
}

// InstalledInSystem reports whether the CA is present in the system trust
// store (best effort: compares against /etc/ssl/certs bundle).
func (ca *CA) InstalledInSystem() bool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		return false
	}
	ca.mu.Lock()
	cert := ca.cert
	ca.mu.Unlock()
	if cert == nil {
		return false
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}
