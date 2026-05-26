package runner

import "fmt"

const version = "1.0.0"

const banner = `
    ______ __             ____   _   __ _____
   / ____// /___   _  __/ __ \ / | / // ___/
  / /_   / // _ \ | |/_// / / //  |/ / \__ \
 / __/  / //  __/_>  < / /_/ // /|  / ___/ /
/_/    /_/ \___//_/|_|/_____//_/ |_/ /____/
`

func PrintBanner(silent bool) {
	if silent {
		return
	}
	fmt.Print(banner)
	fmt.Printf("        v%s - Fast DNS Resolution & Subdomain Enumeration\n\n", version)
}
