package vault

import (
	"time"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
	"gorm.io/gorm"
)

var (
	userKeyExpDur time.Duration = 90 * 24 * time.Hour
	userKeyLen                  = 64
)

type GenUserKeyReq struct {
	Password string `json:"password" valid:"notEmpty"`
	KeyName  string `json:"keyName" valid:"notEmpty"`
}

type NewUserKey struct {
	Name           string
	SecretKey      string
	ExpirationTime miso.ETime
	UserId         int
}

func GenUserKey(rail miso.Rail, tx *gorm.DB, req GenUserKeyReq, username string) error {

	user, err := loadUser(rail, tx, username)
	if err != nil {
		return err
	}

	if !checkPassword(user.Password, user.Salt, req.Password) {
		return miso.NewErrf("Password incorrect, unable to generate user secret key")
	}

	key := miso.RandStr(userKeyLen)
	return tx.Table("user_key").
		Create(NewUserKey{
			Name:           req.KeyName,
			SecretKey:      key,
			ExpirationTime: miso.ETime(time.Now().Add(userKeyExpDur)),
			UserId:         user.Id,
		}).
		Error
}

type ListUserKeysReq struct {
	Paging miso.Paging `json:"pagingVo"`
	Name   string      `json:"name"`
}

type ListedUserKey struct {
	Id             int        `json:"id"`
	SecretKey      string     `json:"secretKey"`
	Name           string     `json:"name"`
	ExpirationTime miso.ETime `json:"expirationTime"`
	CreateTime     miso.ETime `json:"createTime"`
}

func ListUserKeys(rail miso.Rail, tx *gorm.DB, req ListUserKeysReq, user common.User) (miso.PageRes[ListedUserKey], error) {
	qpp := miso.QueryPageParam[ListedUserKey]{
		ReqPage: req.Paging,
		GetBaseQuery: func(tx *gorm.DB) *gorm.DB {
			return tx.Table("user_key").Order("id DESC")
		},
		AddSelectQuery: func(tx *gorm.DB) *gorm.DB {
			return tx.Select("id, secret_key, name, expiration_time, create_time")
		},
		ApplyConditions: func(tx *gorm.DB) *gorm.DB {
			tx = tx.Where("user_id = ?", user.UserId).
				Where("is_del = 0")
			if !miso.IsBlankStr(req.Name) {
				tx = tx.Where("name LIKE ?", "%"+req.Name+"%")
			}
			return tx
		},
	}
	return qpp.ExecPageQuery(rail, tx)
}

type DeleteUserKeyReq struct {
	UserKeyId int `json:"userKeyId"`
}

func DeleteUserKey(rail miso.Rail, tx *gorm.DB, req DeleteUserKeyReq, userId int) error {
	return tx.Exec(`UPDATE user_key SET is_del = 1 WHERE user_id = ? AND id = ? AND is_del = 0`, userId, req.UserKeyId).Error
}
