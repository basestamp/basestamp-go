package basestamp

import (
	"fmt"
	"net/http"
	"runtime"
)

// Version is the basestamp-go SDK version, reported in the User-Agent header.
const Version = "0.2.0"

// UserAgent is the User-Agent sent by Client, e.g. "basestamp-go/0.1.0 (go1.22.1; linux/amd64)".
// It lets the Basestamp service count usage per SDK and version. No other data is sent.
func UserAgent() string {
	return fmt.Sprintf("basestamp-go/%s (%s; %s/%s)", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

type userAgentTransport struct {
	ua   string
	base http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", t.ua)
	}
	return t.base.RoundTrip(r)
}

// NewUserAgentTransport wraps base (or http.DefaultTransport when nil) so every
// request carries ua as its User-Agent unless one is already set.
func NewUserAgentTransport(ua string, base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &userAgentTransport{ua: ua, base: base}
}
