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

type ListedAccessLog struct {
	Id         int        `json:"id"`
	UserAgent  string     `json:"userAgent"`
	IpAddress  string     `json:"ipAddress"`
	UserId     int        `json:"userId"`
	Username   string     `json:"username"`
	Url        string     `json:"url"`
	AccessTime miso.ETime `json:"accessTime"`
}

type ListAccessLogReq struct {
	Paging miso.Paging `json:"pagingVo"`
}

func ListAccessLogs(rail miso.Rail, tx *gorm.DB, req ListAccessLogReq) (miso.PageRes[ListedAccessLog], error) {
	qpm := miso.QueryPageParam[ListAccessLogReq, ListedAccessLog]{
		Req:     req,
		ReqPage: req.Paging,
		AddSelectQuery: func(tx *gorm.DB) *gorm.DB {
			return tx.Select("id", "access_time", "ip_address", "username", "user_id", "url", "user_agent")
		},
		GetBaseQuery: func(tx *gorm.DB) *gorm.DB {
			return tx.Table("access_log").Order("id desc")
		},
		ApplyConditions: func(tx *gorm.DB, req ListAccessLogReq) *gorm.DB { return tx },
	}
	return miso.QueryPage(rail, tx, qpm)
}
