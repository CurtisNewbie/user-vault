package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/bus"
	"github.com/curtisnewbie/miso/core"
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
	AccessTime core.ETime `json:"accessTime"`
}

func sendAccessLogEvnet(rail core.Rail, evt AccessLogEvent) error {
	return bus.SendToEventBus(rail, evt, accessLogEventBus)
}

type AccessLog struct {
	Id         int
	UserAgent  string
	IpAddress  string
	UserId     int
	Username   string
	Url        string
	AccessTime core.ETime
	CreateTime core.ETime
	CreateBy   string
	UpdateTime core.ETime
	UpdateBy   string
	IsDel      common.IS_DEL
}

func SaveAccessLogEvent(rail core.Rail, tx *gorm.DB, evt AccessLogEvent) error {
	return tx.
		Table("access_log").
		Create(evt).
		Error
}
