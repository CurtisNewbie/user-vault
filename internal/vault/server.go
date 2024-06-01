package vault

import (
	"github.com/curtisnewbie/miso/middleware/logbot"
	"github.com/curtisnewbie/miso/middleware/user-vault/common"
	"github.com/curtisnewbie/miso/miso"
)

func BootstrapServer(args []string) {
	common.LoadBuiltinPropagationKeys()
	miso.PreServerBootstrap(func(rail miso.Rail) error {
		rail.Infof("user-vault version: %v", Version)
		return nil
	})
	logbot.EnableLogbotErrLogReport()
	miso.PreServerBootstrap(RegisterRoutes)
	miso.PreServerBootstrap(ScheduleTasks)
	miso.PreServerBootstrap(SubEventBus)
	miso.PostServerBootstrapped(CreateMonitoredServiceWatches)
	miso.BootstrapServer(args)
}
