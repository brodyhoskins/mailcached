package inflate

import (
	"compress/flate"
	"sync"
)

// FlushWriter is the other direction: it compresses and flushes each
// write, as an interactive protocol needs.
type FlushWriter struct {
	mu sync.Mutex
	fw *flate.Writer
}

// NewFlushWriter writes through fw.
func NewFlushWriter(fw *flate.Writer) *FlushWriter { return &FlushWriter{fw: fw} }

func (w *FlushWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.fw.Write(p)
	if err != nil {
		return n, err
	}
	return n, w.fw.Flush()
}
