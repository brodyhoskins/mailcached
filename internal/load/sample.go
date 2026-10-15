package load

import (
	"bufio"
	"bytes"
	"math"
	"os"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"time"
)

// What counts as pressure.
var (
	memHigh    = 0.85                  // of a memory limit in use
	hostMemLow = 0.10                  // of the machine's memory available
	schedSlow  = 10 * time.Millisecond // a goroutine waits this long for a CPU (99th percentile)
	cpuStall   = 0.5                   // of the time, a task waited for a CPU (PSI)
	memStall   = 0.1                   // of the time, a task waited for memory (PSI)
	memShare   = 0.75                  // of the process's memory for the Go memory limit
	swapIn     = 256.0                 // pages a second read back from swap, without PSI
)

// Pressure says what is short. The zero Pressure is none.
type Pressure struct {
	CPU, Memory string // what showed it, "" for no pressure
}

// Any reports whether something is short.
func (p Pressure) Any() bool { return p.CPU != "" || p.Memory != "" }

func (p Pressure) String() string {
	return strings.TrimSpace(strings.Join([]string{p.CPU, p.Memory}, " "))
}

type sampler interface{ sample() Pressure }

// hostSampler reads the pressure from the Go runtime, the cgroup and the
// kernel's pressure stall information (PSI), where the system has them.
type hostSampler struct {
	cgroup  string    // the cgroup v2 directory, "" for none
	psi     [2]string // the PSI files for CPU and memory, "" for none
	at      time.Time
	psiBase bool    // cpuWait and memWait hold a sample
	cpuWait float64 // PSI totals at the last sample, in µs
	memWait float64
	swapped int64 // pages read back from swap, at the last sample
	sched   *metrics.Float64Histogram
	samples []metrics.Sample
}

func newSampler() *hostSampler {
	s := &hostSampler{samples: []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/sched/latencies:seconds"},
	}}
	s.cgroup = cgroupDir()
	// The cgroup's own, else the machine's.
	for _, f := range [][2]string{
		{s.cgroup + "/cpu.pressure", s.cgroup + "/memory.pressure"},
		{"/proc/pressure/cpu", "/proc/pressure/memory"},
	} {
		if s.cgroup == "" && f[0] == "/cpu.pressure" {
			continue
		}
		if psiReadable(f[0]) {
			s.psi = f
			break
		}
	}
	s.sample()
	return s
}

func (s *hostSampler) sample() Pressure {
	var p Pressure
	now := time.Now()
	elapsed := now.Sub(s.at)
	s.at = now

	metrics.Read(s.samples)
	if limit := debug.SetMemoryLimit(-1); limit < math.MaxInt64 {
		used := s.samples[0].Value.Uint64() - s.samples[1].Value.Uint64()
		if float64(used) > memHigh*float64(limit) {
			p.Memory = "go-heap"
		}
	}
	h := s.samples[2].Value.Float64Histogram()
	if s.sched != nil && p99(s.sched, h) > schedSlow {
		p.CPU = "go-scheduler"
	}
	s.sched = clone(h)

	if s.cgroup != "" {
		// The working set: the page cache the kernel can drop aside.
		cur := readInt(s.cgroup+"/memory.current") - statInt(s.cgroup+"/memory.stat", "inactive_file")
		if max := cgroupMemMax(s.cgroup); cur > 0 && max > 0 && float64(cur) > memHigh*float64(max) {
			p.Memory = "cgroup"
		}
	}
	if avail, total := meminfo(); total > 0 && float64(avail) < hostMemLow*float64(total) {
		p.Memory = "host"
	}

	if s.psi[0] != "" {
		cpu, mem := psiTotal(s.psi[0]), psiTotal(s.psi[1])
		if us := float64(elapsed.Microseconds()); s.psiBase && us > 0 {
			if (cpu-s.cpuWait)/us > cpuStall {
				p.CPU = "psi"
			}
			if (mem-s.memWait)/us > memStall {
				p.Memory = "psi"
			}
		}
		s.cpuWait, s.memWait, s.psiBase = cpu, mem, true
	} else if n := statInt("/proc/vmstat", "pswpin"); n > 0 {
		// Without PSI, memory read back from swap is the sign of a
		// machine short of memory.
		if s.swapped > 0 && elapsed > 0 && float64(n-s.swapped)/elapsed.Seconds() > swapIn {
			p.Memory = "swap"
		}
		s.swapped = n
	}
	return p
}

// p99 returns the 99th percentile of the values counted in h since old,
// 0 for too few to tell.
func p99(old, h *metrics.Float64Histogram) time.Duration {
	if len(old.Counts) != len(h.Counts) {
		return 0
	}
	var total uint64
	for i := range h.Counts {
		total += h.Counts[i] - old.Counts[i]
	}
	if total < 20 {
		return 0
	}
	want := total - total/100
	var n uint64
	for i := range h.Counts {
		n += h.Counts[i] - old.Counts[i]
		if n >= want {
			lo := h.Buckets[i] // the bucket's lower bound: never too high
			if math.IsInf(lo, 0) || lo < 0 {
				return 0
			}
			return time.Duration(lo * float64(time.Second))
		}
	}
	return 0
}

func clone(h *metrics.Float64Histogram) *metrics.Float64Histogram {
	return &metrics.Float64Histogram{Counts: append([]uint64(nil), h.Counts...), Buckets: h.Buckets}
}

// psiReadable reports whether path is a PSI file, stalls or none yet.
func psiReadable(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && bytes.HasPrefix(b, []byte("some "))
}

// cgroupDir returns the directory of the process's cgroup (v2), "" if
// there is none: /proc/self/cgroup's "0::" path under /sys/fs/cgroup, or
// the root itself in a container with its own cgroup namespace.
func cgroupDir() string {
	const root = "/sys/fs/cgroup"
	if _, err := os.Stat(root + "/cgroup.controllers"); err != nil {
		return ""
	}
	b, _ := os.ReadFile("/proc/self/cgroup")
	for line := range strings.Lines(string(b)) {
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			dir := root + strings.TrimSuffix(path, "/")
			if _, err := os.Stat(dir + "/memory.current"); err == nil {
				return dir
			}
		}
	}
	return root
}

// cgroupMemMax returns the lowest memory.max of dir and the cgroups above
// it, up to /sys/fs/cgroup; 0 for none.
func cgroupMemMax(dir string) int64 {
	var n int64
	for d := dir; strings.HasPrefix(d, "/sys/fs/cgroup"); d = d[:strings.LastIndex(d, "/")] {
		if m := readInt(d + "/memory.max"); m > 0 && (n == 0 || m < n) {
			n = m
		}
	}
	return n
}

// psiTotal returns the µs some task waited, from the "some" line of a
// PSI file; 0 if there is none.
func psiTotal(path string) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	_, total, ok := bytes.Cut(line, []byte("total="))
	if !bytes.HasPrefix(line, []byte("some ")) || !ok {
		return 0
	}
	n, _ := strconv.ParseFloat(string(bytes.TrimSpace(total)), 64)
	return n
}

// readInt reads a file holding one number; 0 if it holds none, as
// memory.max's "max".
func readInt(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64)
	return n
}

// statInt returns a key's number in a file of "key number" lines, as
// memory.stat.
func statInt(path, key string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for line := range strings.Lines(string(b)) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " "); ok && k == key {
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
	}
	return 0
}

// meminfo returns the machine's available and total memory, 0s where
// /proc/meminfo is missing.
func meminfo() (avail, total int64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), ":")
		n, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		switch k {
		case "MemTotal":
			total = n << 10
		case "MemAvailable":
			avail = n << 10
		}
	}
	return avail, total
}

// setMemoryLimit sets the Go memory limit to memShare of the memory the
// process may use: the cgroup's, else the machine's. SQLite's memory is
// outside the Go heap, hence the share. A GOMEMLIMIT set already wins. It
// returns the limit, 0 for none.
func setMemoryLimit() int64 {
	if os.Getenv("GOMEMLIMIT") != "" {
		return debug.SetMemoryLimit(-1)
	}
	var n int64
	if dir := cgroupDir(); dir != "" {
		n = cgroupMemMax(dir)
	}
	if n <= 0 {
		_, n = meminfo()
	}
	if n <= 0 {
		return 0
	}
	l := int64(memShare * float64(n))
	debug.SetMemoryLimit(l)
	return l
}
