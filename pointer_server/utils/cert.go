package utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

var SkipVerify = true
var UTC = false
var CipherSuite = ""
var userTempl string
var timeoutSeconds = Config.HttpDelay

const defaultPort = "50050"

var cipherSuites = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
}

func SplitHostPort(hostport string) (string, string, error) {
	if !strings.Contains(hostport, ":") {
		return hostport, defaultPort, nil
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", "", err
	}

	if port == "" {
		port = defaultPort
	}

	return host, port, nil
}

type Cert struct {
	DomainName string
	IP         string
	Issuer     string
	CommonName string
	SANs       []string
	NotBefore  string
	NotAfter   string
	Error      string
	certChain  []*x509.Certificate
}

func cipherSuite() ([]uint16, error) {
	if CipherSuite == "" {
		return nil, nil
	}

	var cs []uint16
	cs = []uint16{cipherSuites[CipherSuite]}
	if cs[0] == 0 {
		return nil, fmt.Errorf("%s is unsupported cipher suite or tls1.3 cipher suite.", CipherSuite)
	}
	return cs, nil
}

func tlsVersion() uint16 {
	if CipherSuite != "" {
		return tls.VersionTLS12
	}
	// Currently TLS 1.3
	return 0
}

var serverCert = func(host, port string) ([]*x509.Certificate, string, error) {
	d := &net.Dialer{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}

	cs, err := cipherSuite()
	if err != nil {
		return []*x509.Certificate{&x509.Certificate{}}, "", err
	}

	conn, err := tls.DialWithDialer(d, "tcp", host+":"+port, &tls.Config{
		InsecureSkipVerify: SkipVerify,
		CipherSuites:       cs,
		MaxVersion:         tlsVersion(),
	})
	if err != nil {
		return []*x509.Certificate{&x509.Certificate{}}, "", err
	}
	defer conn.Close()

	addr := conn.RemoteAddr()
	ip, _, _ := net.SplitHostPort(addr.String())
	cert := conn.ConnectionState().PeerCertificates

	return cert, ip, nil
}

func NewCert(hostport string) *Cert {
	host, port, err := SplitHostPort(hostport)
	if err != nil {
		return &Cert{DomainName: host, Error: err.Error()}
	}
	certChain, ip, err := serverCert(host, port)
	if err != nil {
		return &Cert{DomainName: host, Error: err.Error()}
	}
	cert := certChain[0]

	var loc *time.Location
	loc = time.Local
	if UTC {
		loc = time.UTC
	}

	return &Cert{
		DomainName: host,
		IP:         ip,
		Issuer:     cert.Issuer.CommonName,
		CommonName: cert.Subject.CommonName,
		SANs:       cert.DNSNames,
		NotBefore:  cert.NotBefore.In(loc).String(),
		NotAfter:   cert.NotAfter.In(loc).String(),
		Error:      "",
		certChain:  certChain,
	}
}

// For future extending maybe
func (c *Cert) Detail() *x509.Certificate {
	return c.certChain[0]
}
