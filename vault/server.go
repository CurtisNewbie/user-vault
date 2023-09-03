package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/bus"
	"github.com/curtisnewbie/miso/core"
	"github.com/curtisnewbie/miso/mysql"
	"github.com/curtisnewbie/miso/server"
)

func BootstrapServer(args []string) {
	common.LoadBuiltinPropagationKeys()

	server.PreServerBootstrap(func(rail core.Rail) error {
		if er := prepareEventBus(rail); er != nil {
			return er
		}
		return registerRoutes(rail)
	})

	server.BootstrapServer(args)
}

func prepareEventBus(rail core.Rail) error {
	if er := bus.DeclareEventBus(accessLogEventBus); er != nil {
		return er
	}

	bus.SubscribeEventBus[AccessLogEvent](accessLogEventBus, 2, func(rail core.Rail, evt AccessLogEvent) error {
		rail.Infof("Received AccessLogEvent: %+v", evt)
		return SaveAccessLogEvent(rail, mysql.GetConn(), evt)
	})

	return nil
}
