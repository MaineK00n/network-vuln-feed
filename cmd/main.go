package main

import (
	"fmt"
	"os"

	rootCmd "github.com/MaineK00n/network-vuln-feed/pkg/cmd/root"
)

func main() {
	if err := rootCmd.NewCmdRoot().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to exec network-vuln-feed: %s\n", fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
}
