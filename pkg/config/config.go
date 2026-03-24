// Package config holds runtime options passed from main.
package config

// Run is the set of flags and positional command for one execution.
type Run struct {
	// Command is the first positional argument (encrypt or decrypt phrase).
	Command string

	// Root is the directory tree to scan. Empty means use OS default root (see filedirectory.RootDir).
	Root string

	// Workers is the number of parallel file workers (must be >= 1).
	Workers int

	// DryRun logs what would happen without writing ciphertext/plaintext or deleting originals.
	DryRun bool

	// MaxFileSize is the maximum file size in bytes to read/encrypt/decrypt. 0 means no limit.
	MaxFileSize int64
}
