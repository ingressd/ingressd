// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Parsers for the Linux /proc files the metrics collector reads. They take
// the file contents so they are testable on any platform (testdata/proc).

// cpuTimes are the aggregate "cpu" jiffies of /proc/stat.
type cpuTimes struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func (c cpuTimes) total() uint64 {
	// guest time is already included in user and nice.
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

// parseProcStat returns the aggregate CPU times and the number of CPUs.
func parseProcStat(b []byte) (cpuTimes, int, error) {
	var c cpuTimes
	found, cores := false, 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if f[0] != "cpu" {
			cores++
			continue
		}
		v := make([]uint64, 8)
		for i := range v {
			if i+1 < len(f) {
				v[i], _ = strconv.ParseUint(f[i+1], 10, 64)
			}
		}
		c = cpuTimes{v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]}
		found = true
	}
	if !found {
		return c, 0, errors.New("/proc/stat: no cpu line")
	}
	return c, cores, nil
}

func parseLoadavg(b []byte) ([3]float64, error) {
	var l [3]float64
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return l, errors.New("/proc/loadavg: short")
	}
	for i := range l {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return l, err
		}
		l[i] = v
	}
	return l, nil
}

// memInfo holds /proc/meminfo values in bytes.
type memInfo struct {
	total, available, swapTotal, swapFree int64
}

func parseMeminfo(b []byte) (memInfo, error) {
	var m memInfo
	seen := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			n *= 1024
		}
		switch k {
		case "MemTotal":
			m.total = n
			seen++
		case "MemAvailable":
			m.available = n
			seen++
		case "SwapTotal":
			m.swapTotal = n
		case "SwapFree":
			m.swapFree = n
		}
	}
	if seen < 2 {
		return m, errors.New("/proc/meminfo: no MemTotal/MemAvailable")
	}
	return m, nil
}

// ifCounters are one interface's /proc/net/dev counters.
type ifCounters struct {
	rxBytes, rxPackets, rxErrs, rxDrop uint64
	txBytes, txPackets, txErrs, txDrop uint64
}

func (c *ifCounters) addTo(o ifCounters) {
	c.rxBytes += o.rxBytes
	c.rxPackets += o.rxPackets
	c.rxErrs += o.rxErrs
	c.rxDrop += o.rxDrop
	c.txBytes += o.txBytes
	c.txPackets += o.txPackets
	c.txErrs += o.txErrs
	c.txDrop += o.txDrop
}

func parseNetDev(b []byte) map[string]ifCounters {
	out := map[string]ifCounters{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 16 {
			continue
		}
		n := make([]uint64, 16)
		for i := range n {
			n[i], _ = strconv.ParseUint(f[i], 10, 64)
		}
		out[strings.TrimSpace(name)] = ifCounters{
			rxBytes: n[0], rxPackets: n[1], rxErrs: n[2], rxDrop: n[3],
			txBytes: n[8], txPackets: n[9], txErrs: n[10], txDrop: n[11],
		}
	}
	return out
}

// parseRoute returns the interface of the IPv4 default route.
func parseRoute(b []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 8 && f[1] == "00000000" && f[7] == "00000000" {
			return f[0]
		}
	}
	return ""
}

// parseTCP counts ESTABLISHED sockets in /proc/net/tcp{,6} and how many of
// them have one of ports as their local port.
func parseTCP(b []byte, ports map[uint64]bool) (established, onPorts int) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != "01" {
			continue
		}
		established++
		if i := strings.LastIndexByte(f[1], ':'); i >= 0 {
			if p, err := strconv.ParseUint(f[1][i+1:], 16, 16); err == nil && ports[p] {
				onPorts++
			}
		}
	}
	return established, onPorts
}

// parseDiskstats returns sectors read and written by dev.
func parseDiskstats(b []byte, dev string) (read, written uint64, ok bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[2] != dev {
			continue
		}
		read, _ = strconv.ParseUint(f[5], 10, 64)
		written, _ = strconv.ParseUint(f[9], 10, 64)
		return read, written, true
	}
	return 0, 0, false
}

// parseMounts returns the block device (e.g. "sda1") mounted at the
// longest mount point containing path, or "" if that is not a /dev device.
func parseMounts(b []byte, path string) string {
	best, dev := -1, ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		mp := strings.ReplaceAll(f[1], `\040`, " ")
		if !pathWithin(path, mp) || len(mp) <= best {
			continue
		}
		best = len(mp)
		dev = ""
		if d, ok := strings.CutPrefix(f[0], "/dev/"); ok && !strings.Contains(d, "/") {
			dev = d
		}
	}
	return dev
}

func pathWithin(path, dir string) bool {
	if dir == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// parseStatusRSS returns VmRSS from /proc/<pid>/status in bytes.
func parseStatusRSS(b []byte) (int64, bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		v, ok := strings.CutPrefix(sc.Text(), "VmRSS:")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			return 0, false
		}
		n, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			return 0, false
		}
		return n * 1024, true
	}
	return 0, false
}

func parseInt(b []byte) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n, err == nil
}

// findProcess returns the pid of the first process under root/proc whose
// comm is one of names.
func findProcess(root string, names ...string) string {
	ents, err := os.ReadDir(filepath.Join(root, "proc"))
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, "proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(b))
		for _, n := range names {
			if comm == n {
				return e.Name()
			}
		}
	}
	return ""
}
