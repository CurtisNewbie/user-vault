package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
)

func BootstrapServer(args []string) {
	common.LoadBuiltinPropagationKeys()
	miso.PreServerBootstrap(prepareEventBus)
	miso.PreServerBootstrap(registerRoutes)
	miso.BootstrapServer(args)
}

func prepareEventBus(rail miso.Rail) error {
	miso.SubEventBus(accessLogEventBus, 2, func(rail miso.Rail, evt AccessLogEvent) error {
		rail.Infof("Received AccessLogEvent: %+v", evt)
		return SaveAccessLogEvent(rail, miso.GetMySQL(), evt)
	})

	return nil
}
