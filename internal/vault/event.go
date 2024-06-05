package vault

import (
	"github.com/curtisnewbie/miso/middleware/rabbit"
	"github.com/curtisnewbie/miso/miso"
)

var (
	AccessLogPipeline = rabbit.NewEventPipeline[AccessLogEvent]("event.bus.user-vault.access.log").
		LogPayload().
		MaxRetry(2).
		Listen(2, func(rail miso.Rail, evt AccessLogEvent) error {
			rail.Infof("Received AccessLogEvent: %+v", evt)
			return SaveAccessLogEvent(rail, miso.GetMySQL(), SaveAccessLogParam(evt))
		})
)

type AccessLogEvent struct {
	UserAgent  string
	IpAddress  string
	UserId     int
	Username   string
	Url        string
	Success    bool
	AccessTime miso.ETime
}
