package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var tbusCmd = &cobra.Command{
	Use:   "tbus",
	Short: "tbus is a simple firewall based on XDP.",
}

func init() {
	tbusCmd.AddCommand(wallCmd)
}

func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	os.Exit(0)
}

func main() {
	if err := tbusCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
