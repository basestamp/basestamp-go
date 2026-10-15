package cli

import (
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/basestamp/basestamp-go"
)

// cliHTTP identifies CLI traffic as "basestamp-cli/<version>" so the service can
// count usage per client. No other telemetry is collected.
var cliHTTP = &http.Client{
	Timeout:   60 * time.Second,
	Transport: basestamp.NewUserAgentTransport(fmt.Sprintf("basestamp-cli/%s (%s; %s/%s)", basestamp.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH), nil),
}
