package main

import (
	"os"

	"github.com/curtisnewbie/miso/server"
)


func main() {
	server.BootstrapServer(os.Args)
}