package filedirectory

import (
	"fmt"
	"sync"
)

// FileOpResult records the outcome of a single file operation.
type FileOpResult struct {
	WorkerID int
	Path     string
	Op       string // "encrypt" | "decrypt"
	OK       bool
	Err      error
	DryRun   bool
	Skipped  bool
	Reason   string
}

// ResultReport aggregates per-file results for a final summary.
type ResultReport struct {
	mu sync.Mutex

	EncryptOK      int
	EncryptFail    int
	EncryptSkipped int
	DecryptOK      int
	DecryptFail    int
	DecryptSkipped int
	DryRun         bool
}

// NewResultReport creates an empty report.
func NewResultReport(dryRun bool) *ResultReport {
	return &ResultReport{DryRun: dryRun}
}

// Add records one result and updates counters.
func (r *ResultReport) Add(res FileOpResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if res.Op == "encrypt" {
		if res.Skipped {
			r.EncryptSkipped++
			return
		}
		if res.OK {
			r.EncryptOK++
		} else {
			r.EncryptFail++
		}
		return
	}
	if res.Op == "decrypt" {
		if res.Skipped {
			r.DecryptSkipped++
			return
		}
		if res.OK {
			r.DecryptOK++
		} else {
			r.DecryptFail++
		}
	}
}

// Summary returns a human-readable line suitable for logs.
func (r *ResultReport) Summary() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	prefix := ""
	if r.DryRun {
		prefix = "[dry-run] "
	}
	return fmt.Sprintf(
		"%sencrypt: ok=%d fail=%d skipped=%d | decrypt: ok=%d fail=%d skipped=%d",
		prefix,
		r.EncryptOK, r.EncryptFail, r.EncryptSkipped,
		r.DecryptOK, r.DecryptFail, r.DecryptSkipped,
	)
}
