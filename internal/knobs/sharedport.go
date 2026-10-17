package knobs

import "strings"

// HTTPForwardingID is the shared-port endpoint to which HTCondor's shared
// port passes connections that begin like an HTTP request or a TLS
// ClientHello: SHARED_PORT_HTTP_FORWARDING_ID, else http_api when
// DAEMON_LIST names HTTP_API, else none (shared_port_server.cpp,
// HTCondor 25.7.2 and later).
func HTTPForwardingID(cfg Getter) string {
	if id := String(cfg, "SHARED_PORT_HTTP_FORWARDING_ID", ""); id != "" {
		return id
	}
	for _, d := range List(cfg, "DAEMON_LIST", nil) {
		if strings.EqualFold(d, "HTTP_API") {
			return "http_api"
		}
	}
	return ""
}
