package main

import (
	"os"

	"github.com/curtisnewbie/user-vault/internal/vault"
)

func main() {
	vault.BootstrapServer(os.Args)
}
