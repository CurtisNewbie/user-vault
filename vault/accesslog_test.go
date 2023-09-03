package vault

import (
	"testing"

	"github.com/curtisnewbie/miso/core"
	"github.com/curtisnewbie/miso/mysql"
	"github.com/curtisnewbie/miso/rabbitmq"
)

func preAccessLogTest(t *testing.T) core.Rail {
	rail := preTest(t)
	core.TestIsNil(t, mysql.InitMySqlFromProp())
	core.TestIsNil(t, rabbitmq.StartRabbitMqClient(rail.Ctx))
	return rail
}

func TestSendAccessLogEvent(t *testing.T) {
	rail := preAccessLogTest(t)
	er := sendAccessLogEvnet(rail, AccessLogEvent{
		IpAddress:  "127.0.0.1",
		UserAgent:  "Linux Ubuntu",
		UserId:     0,
		Username:   "yongj.zhuang",
		Url:        passwordLoginUrl,
		AccessTime: core.Now(),
	})

	core.TestIsNil(t, er)
}
