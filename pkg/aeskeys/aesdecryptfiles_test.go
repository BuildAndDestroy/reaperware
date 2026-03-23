package aeskeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewAESDecryptorRejectsOversizedFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "big.reaperware")
	data := make([]byte, 100)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)

	_, err := NewAESDecryptor(key, p, 50)
	if err == nil {
		t.Fatal("expected error when encrypted file exceeds max size")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}

	// At the limit: stat allows load into memory (constructor does not validate GCM payload).
	_, err = NewAESDecryptor(key, p, 100)
	if err != nil {
		t.Fatalf("100-byte file with max 100 should pass stat/read: %v", err)
	}
}
