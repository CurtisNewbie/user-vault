package main

import (
	"os"

	"github.com/curtisnewbie/user-vault/vault"
)


func main() {
	vault.BootstrapServer(os.Args)
}