package vault

import (
	"github.com/curtisnewbie/miso/miso"
)

func SubEventBus(rail miso.Rail) error {
	miso.SubEventBus(accessLogEventBus, 2, func(rail miso.Rail, evt AccessLogEvent) error {
		rail.Infof("Received AccessLogEvent: %+v", evt)
		return SaveAccessLogEvent(rail, miso.GetMySQL(), SaveAccessLogParam(evt))
	})

	return nil
}

type AccessLogEvent struct {
	UserAgent  string
	IpAddress  string
	UserId     int
	Username   string
	Url        string
	Success    bool
	AccessTime miso.ETime
}

func sendAccessLogEvnet(rail miso.Rail, evt AccessLogEvent) error {
	return miso.PubEventBus(rail, evt, accessLogEventBus)
}
