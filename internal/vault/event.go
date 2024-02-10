package vault

import (
	"github.com/curtisnewbie/miso/miso"
)

func SubEventBus(rail miso.Rail) error {
	miso.SubEventBus(accessLogEventBus, 2, func(rail miso.Rail, evt AccessLogEvent) error {
		rail.Infof("Received AccessLogEvent: %+v", evt)
		return SaveAccessLogEvent(rail, miso.GetMySQL(), evt)
	})

	return nil
}
