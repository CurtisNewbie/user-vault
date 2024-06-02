package postbox

import (
	"fmt"

	"github.com/curtisnewbie/miso/middleware/user-vault/common"
	"github.com/curtisnewbie/miso/miso"
	"github.com/curtisnewbie/postbox/api"
	"gorm.io/gorm"
)

const (
	StatusInit   = "INIT"
	StatusOpened = "OPENED"
)

var (
	ErrUserNotFound = miso.NewErrf("User not found").WithCode(api.CodeUserNotFound)
)

func CreateNotification(rail miso.Rail, db *gorm.DB, req api.CreateNotificationReq, user common.User) error {
	if len(req.ReceiverUserNos) < 1 {
		return nil
	}

	// check whether the userNos are leegal
	req.ReceiverUserNos = miso.Distinct(req.ReceiverUserNos)

	// aw := miso.NewAwaitFutures[string](PostboxPool)
	// for i := range req.ReceiverUserNos {
	// 	userNo := req.ReceiverUserNos[i]
	// aw.SubmitAsync(func() (string, error) {
	// 	_, err := uservault.FindUser(rail.NextSpan(), uservault.FindUserReq{
	// 		UserNo: &userNo,
	// 	})
	// 	if err != nil {
	// 		rail.Errorf("failed to FindUser, %v", err)
	// 		return userNo, err
	// 	}
	// 	return userNo, err
	// })
	// }
	// futures := aw.Await()
	// for _, f := range futures {
	// 	if userNo, err := f.Get(); err != nil {
	// 		return ErrUserNotFound.WithInternalMsg("failed to FindUser, userNo: %v, %v", userNo, err)
	// 	}
	// }

	for _, u := range req.ReceiverUserNos {
		sr := SaveNotifiReq{
			UserNo:  u,
			Title:   req.Title,
			Message: req.Message,
		}
		if err := SaveNotification(rail, db, sr, user); err != nil {
			return fmt.Errorf("failed to save notification, %+v, %v", sr, err)
		}
	}

	return nil
}

type SaveNotifiReq struct {
	UserNo  string
	Title   string
	Message string
}

func SaveNotification(rail miso.Rail, db *gorm.DB, req SaveNotifiReq, user common.User) error {
	notifiNo := NotifiNo()
	err := db.Exec(`insert into notification (user_no, notifi_no, title, message, created_by) values (?, ?, ?, ?, ?)`,
		req.UserNo, notifiNo, req.Title, req.Message, user.Username).Error
	if err != nil {
		return fmt.Errorf("failed to save notifiication record, %+v", req)
	}
	return nil
}

func NotifiNo() string {
	return miso.GenIdP("notif_")
}

type ListedNotification struct {
	Id         int
	NotifiNo   string
	Title      string
	Message    string
	Status     string
	CreateTime miso.ETime
}

func QueryNotification(rail miso.Rail, db *gorm.DB, req QueryNotificationReq, user common.User) (miso.PageRes[ListedNotification], error) {
	return miso.NewPageQuery[ListedNotification]().
		WithPage(req.Page).
		WithBaseQuery(func(tx *gorm.DB) *gorm.DB {
			return tx.Table("notification")
		}).
		WithSelectQuery(func(tx *gorm.DB) *gorm.DB {
			tx = tx.Select("id, notifi_no, title, message, status, create_time").
				Order("id desc").
				Limit(req.Page.GetLimit()).
				Offset(req.Page.GetOffset())

			tx = tx.Where("user_no = ?", user.UserNo)
			if req.Status != "" {
				tx = tx.Where("status = ?", req.Status)
			}
			return tx
		}).
		Exec(rail, db)
}

func CountNotification(rail miso.Rail, db *gorm.DB, user common.User) (int, error) {
	var count int
	err := db.Table("notification").
		Select("count(*)").
		Where("user_no = ?", user.UserNo).
		Where("status = ?", StatusInit).
		Scan(&count).Error
	return count, err
}

func OpenNotification(rail miso.Rail, db *gorm.DB, req OpenNotificationReq, user common.User) error {
	return db.Exec(`UPDATE notification SET status = ?, updated_by = ? WHERE notifi_no = ? AND user_no = ?`,
		StatusOpened, user.Username, req.NotifiNo, user.UserNo).Error
}

func OpenAllNotification(rail miso.Rail, db *gorm.DB, user common.User) error {
	return db.Exec(`UPDATE notification SET status = ?, updated_by = ? WHERE user_no = ? AND status = ?`,
		StatusOpened, user.Username, user.UserNo, StatusInit).Error
}
