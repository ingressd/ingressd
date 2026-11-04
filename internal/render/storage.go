// SPDX-License-Identifier: Apache-2.0

package render

// StorageLocalPrefixes are certmagic key prefixes the shared storage module
// keeps on the node only: Caddy's internal CA (pki/) is per node, so its
// root (reported to the panel, trusted by connectors) does not change when
// a node joins shared storage.
var StorageLocalPrefixes = []string{"pki"}

// renderStorage returns Caddy's top-level storage config: the shared
// caddy.storage.ingressd module in managed mode, file_system otherwise,
// nil (Caddy's default) when neither is configured.
func renderStorage(opts Options) obj {
	switch {
	case opts.StorageSocket != "":
		st := obj{"module": "ingressd", "socket": opts.StorageSocket, "local_prefixes": StorageLocalPrefixes}
		if opts.StorageDir != "" {
			st["cache_dir"] = opts.StorageDir
		}
		return st
	case opts.StorageDir != "":
		return obj{"module": "file_system", "root": opts.StorageDir}
	}
	return nil
}
