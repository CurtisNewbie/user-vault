package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/core"
	"github.com/curtisnewbie/miso/server"
)

func BootstrapServer(args []string) {
	common.LoadBuiltinPropagationKeys()
	server.PreServerBootstrap(func(rail core.Rail) error {
		return registerRoutes(rail)
	})
	server.BootstrapServer(args)
}
