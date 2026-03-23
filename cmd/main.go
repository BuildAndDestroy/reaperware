package main

import (
	"log"
	"reaperware/pkg/userinput"
	"time"
)

// Execute the program
func main() {
	initStart := time.Now()
	userinput.UserCommands()

	elapsedStart := time.Since(initStart)
	log.Println("[*] Time from the very beginning:", elapsedStart)
}
