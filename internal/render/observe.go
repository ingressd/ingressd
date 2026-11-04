// SPDX-License-Identifier: Apache-2.0

package render

// Access logs (PLAN §13): every request on the edge server is logged as
// JSON to a unix socket owned by the control plane (internal/observe). The
// same stream carries Caddy's certificate obtain/renew logs, which the
// control plane turns into cert_renewal_failed alerts.

const (
	// AccessLoggerName is the server's access logger; Caddy emits entries
	// from the logger "http.log.access." + AccessLoggerName.
	AccessLoggerName = "ingressd_access"
	// Keys of the two Caddy logs writing to the socket.
	accessLogKey = "ingressd_access"
	eventLogKey  = "ingressd_events"
)

// EventLoggers are the Caddy loggers forwarded besides access logs.
var EventLoggers = []string{"tls.obtain", "tls.renew"}

func renderLogging(root, httpApp obj, opts Options) {
	if opts.AccessLogSocket == "" {
		return
	}
	// soft_start: Caddy still loads (logging to stderr and redialling) when
	// the control plane is not running.
	writer := obj{"output": "net", "address": "unix/" + opts.AccessLogSocket, "soft_start": true, "dial_timeout": "2s"}
	all := append([]string{"http.log.access." + AccessLoggerName}, EventLoggers...)
	root["logging"] = obj{"logs": obj{
		// Keep access logs out of Caddy's stderr; event loggers still go
		// there too, which is useful in journald.
		"default":    obj{"exclude": []string{"http.log.access." + AccessLoggerName}},
		accessLogKey: obj{"writer": writer, "encoder": obj{"format": "json"}, "include": all[:1]},
		eventLogKey:  obj{"writer": writer, "encoder": obj{"format": "json"}, "include": all[1:], "level": "INFO"},
	}}
	for _, s := range httpApp["servers"].(obj) {
		s.(obj)["logs"] = obj{"default_logger_name": AccessLoggerName}
	}
}
