// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package nodeagent

// procRoot is empty where there is no Linux /proc: the metrics collector
// then reports only cores, disk space (Unix), edge and tunnel figures.
const procRoot = ""
