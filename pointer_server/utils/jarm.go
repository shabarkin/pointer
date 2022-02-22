package utils

import (
	"fmt"
	"net"
	"strings"
	"time"

	jarm "github.com/RumbleDiscovery/jarm-go"
	"golang.org/x/net/proxy"
)

// Fingerprint probes a single host/port
func JarmFingerprint(t Target) Result {

	results := []string{}
	for _, probe := range jarm.GetProbes(t.Host, t.Port) {
		dialer := proxy.FromEnvironmentUsing(&net.Dialer{Timeout: time.Second * 2})
		addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port))

		c := net.Conn(nil)
		n := 0

		for c == nil && n <= t.Retries {
			// Ignoring error since error message was already being dropped.
			// Also, if theres an error, c == nil.
			if c, _ = dialer.Dial("tcp", addr); c != nil || t.Retries == 0 {
				break
			}

			time.Sleep(DefualtBackoff(n, t.Retries))
			n++
		}

		if c == nil {
			return Result{
				Target: t,
				Hash:   "",
			}
		}

		data := jarm.BuildProbe(probe)
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		_, err := c.Write(data)
		if err != nil {
			results = append(results, "")
			c.Close()
			continue
		}

		c.SetReadDeadline(time.Now().Add(time.Second * 5))
		buff := make([]byte, 1484)
		c.Read(buff)
		c.Close()

		ans, err := jarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}

		results = append(results, ans)
	}

	return Result{
		Target: t,
		Hash:   jarm.RawHashToFuzzyHash(strings.Join(results, ",")),
	}
}

var DefualtBackoff = func(r, m int) time.Duration {
	return time.Second
}

type Target struct {
	Host    string
	Port    int
	Retries int
}

type Result struct {
	Target Target
	Hash   string
	Error  error
}
