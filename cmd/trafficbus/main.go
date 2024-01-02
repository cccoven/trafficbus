package main

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tbus",
	Short: "tbus is a simple firewall based on XDP.",
	Long:  "",
}

var wallCmd = &cobra.Command{
	Use:   "wall",
	Short: "Module firewall",
	Long:  "",
	Run:   func(cmd *cobra.Command, args []string) {},
}

var wallRunCmd = &cobra.Command{
	Use: "run",
	Short: "run firewall",
}

func init() {
	wallCmd.AddCommand(wallRunCmd)
	rootCmd.AddCommand(wallCmd)
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	// c := make(chan os.Signal, 1)
	// signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	// <-c
	// os.Exit(0)
}
