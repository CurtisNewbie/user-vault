package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
	"gorm.io/gorm"
)

const (
	accessLogEventBus = "event.bus.user-vault.access.log"
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
	Username   string     `json:"username"`
	Url        string     `json:"url"`
	AccessTime miso.ETime `json:"accessTime"`
}

type ListAccessLogReq struct {
	Paging miso.Paging `json:"pagingVo"`
}

func ListAccessLogs(rail miso.Rail, tx *gorm.DB, user common.User, req ListAccessLogReq) (miso.PageRes[ListedAccessLog], error) {
	qpp := miso.QueryPageParam[ListedAccessLog]{
		ReqPage: req.Paging,
		AddSelectQuery: func(tx *gorm.DB) *gorm.DB {
			return tx.Select("id", "access_time", "ip_address", "username", "url", "user_agent")
		},
		GetBaseQuery: func(tx *gorm.DB) *gorm.DB {
			return tx.Table("access_log").Order("id desc").Where("user_id = ?", user.UserId)
		},
	}
	return qpp.ExecPageQuery(rail, tx)
}
