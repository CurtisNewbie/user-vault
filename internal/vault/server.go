package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
)

func BootstrapServer(args []string) {
	common.LoadBuiltinPropagationKeys()
	miso.PreServerBootstrap(RegisterRoutes)
	miso.PreServerBootstrap(ScheduleTasks)
	miso.PreServerBootstrap(SubEventBus)
	miso.PostServerBootstrapped(CreateMonitoredServiceWatches)
	miso.BootstrapServer(args)
}
