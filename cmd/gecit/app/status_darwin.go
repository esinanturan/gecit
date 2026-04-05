package app

import (
	"fmt"
	"os"

	"github.com/boratanrikulu/gecit/pkg/proxy"
)

func printPlatformStatus() {
	fmt.Printf("  engine:     http-connect\n")

	if os.Geteuid() != 0 {
		fmt.Printf("  (run with sudo for accurate capability detection)\n")
		return
	}

	iface, err := proxy.DefaultInterface()
	if err != nil {
		fmt.Printf("  interface:  not detected\n")
	} else {
		fmt.Printf("  interface:  %s\n", iface)
	}

	fmt.Printf("  raw socket: available\n")
}
