//go:build !windows

package main

import (
	"fmt"

	"github.com/twopiq/antivirus/internal/ui"
)

func (a *app) install() int {
	fmt.Println(ui.Yellow("O'rnatish faqat Windows'da qo'llab-quvvatlanadi."))
	return 1
}

func (a *app) uninstall(purge bool) int {
	fmt.Println(ui.Yellow("Faqat Windows'da qo'llab-quvvatlanadi."))
	return 1
}

func protectionStatus() (installed, running bool, tasks map[string]bool) {
	return false, false, nil
}
