package vault

import (
	"testing"

	"github.com/curtisnewbie/miso/miso"
)

func preAccessLogTest(t *testing.T) miso.Rail {
	rail := preTest(t)
	if e := miso.InitMySQLFromProp(rail); e != nil {
		t.Fatal(e)
	}
	if e := miso.StartRabbitMqClient(rail); e != nil {
		t.Fatal(e)
	}
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
		AccessTime: miso.Now(),
	})

	if er != nil {
		t.Fatal(er)
	}
}
