package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
	"gorm.io/gorm"
)

const (
	accessLogEventBus = "user-vault.access.log"
)

type AccessLogEvent struct {
	UserAgent  string     `json:"userAgent"`
	IpAddress  string     `json:"ipAddress"`
	UserId     int        `json:"userId"`
	Username   string     `json:"username"`
	Url        string     `json:"url"`
	AccessTime miso.ETime `json:"accessTime"`
}

func sendAccessLogEvnet(rail miso.Rail, evt AccessLogEvent) error {
	return miso.PubEventBus(rail, evt, accessLogEventBus)
}

type AccessLog struct {
	Id         int
	UserAgent  string
	IpAddress  string
	UserId     int
	Username   string
	Url        string
	AccessTime miso.ETime
	CreateTime miso.ETime
	CreateBy   string
	UpdateTime miso.ETime
	UpdateBy   string
	IsDel      common.IS_DEL
}

func SaveAccessLogEvent(rail miso.Rail, tx *gorm.DB, evt AccessLogEvent) error {
	return tx.
		Table("access_log").
		Create(&evt).
		Error
}
