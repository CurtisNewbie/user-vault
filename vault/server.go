package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
)

func BootstrapServer(args []string) {
	common.LoadBuiltinPropagationKeys()

	miso.PreServerBootstrap(func(rail miso.Rail) error {
		if er := prepareEventBus(rail); er != nil {
			return er
		}
		return registerRoutes(rail)
	})

	miso.BootstrapServer(args)
}

func prepareEventBus(rail miso.Rail) error {
	if er := miso.NewEventBus(accessLogEventBus); er != nil {
		return er
	}

	miso.SubEventBus(accessLogEventBus, 2, func(rail miso.Rail, evt AccessLogEvent) error {
		rail.Infof("Received AccessLogEvent: %+v", evt)
		return SaveAccessLogEvent(rail, miso.GetMySQL(), evt)
	})

	return nil
}
