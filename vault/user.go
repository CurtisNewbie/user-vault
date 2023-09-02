package vault

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/core"
	"github.com/curtisnewbie/miso/jwt"
	"gorm.io/gorm"
)

type PasswordLoginReq struct {
	RemoteAddr string
	UserAgent  string
	Username   string
	Password   string
}

type ReviewStatusType string
type UserDisabledType int

type User struct {
	Id           int
	UserNo       string
	Username     string
	Password     string
	Salt         string
	ReviewStatus ReviewStatusType
	RoleNo       string
	IsDisabled   UserDisabledType
	CreateTime   core.ETime
	CreateBy     string
	UpdateTime   core.ETime
	UpdateBy     string
	IsDel        common.IS_DEL
}

const (
	ReviewPending  ReviewStatusType = "PENDING"
	ReviewRejected ReviewStatusType = "REJECTED"
	ReviewApproved ReviewStatusType = "APPROVED"

	UserNormal   UserDisabledType = 0
	UserDisabled UserDisabledType = 1
)

func RemoteAddr(forwardedFor string) string {
	addr := "unknown"

	if forwardedFor != "" {
		tkn := strings.Split(forwardedFor, ",")
		if len(tkn) > 0 {
			addr = tkn[0]
		}
	}
	return addr
}

func loadUser(rail core.Rail, tx *gorm.DB, username string) (User, error) {
	if username == "" {
		return User{}, core.NewWebErr("Username is required")
	}

	var user User
	t := tx.Raw(`SELECT * FROM user WHERE username = ? and is_del = 0`, username).
		Scan(&user)

	if t.Error != nil {
		rail.Errorf("Failed to find user, username: %v, %v", username, t.Error)
		return User{}, t.Error
	}

	if t.RowsAffected < 1 {
		return User{}, core.NewWebErr("User not found", fmt.Sprintf("User %v is not found", username))
	}

	return user, nil
}

func UserLogin(rail core.Rail, tx *gorm.DB, req PasswordLoginReq) (string, error) {
	user, err := userLogin(rail, tx, req.Username, req.Password)
	if err != nil {
		return "", err
	}
	return buildToken(user)
}

func buildToken(user User) (string, error) {
	claims := map[string]any{
		"id":       user.Id,
		"username": user.Username,
		"userno":   user.UserNo,
		"roleno":   user.RoleNo,
	}

	return jwt.EncodeToken(claims, 15*time.Minute)
}

func userLogin(rail core.Rail, tx *gorm.DB, username string, password string) (User, error) {
	if core.IsBlankStr(username) {
		return User{}, core.NewWebErr("Username is required")
	}

	if core.IsBlankStr(password) {
		return User{}, core.NewWebErr("Password is required")
	}

	user, err := loadUser(rail, tx, username)
	if err != nil {
		return User{}, err
	}

	if user.ReviewStatus == ReviewPending {
		return User{}, core.NewWebErr("Your Registration is being reviewed, please wait for approval")
	}

	if user.ReviewStatus == ReviewRejected {
		return User{}, core.NewWebErr("Your are not permitted to login, please contact administrator")
	}

	if user.IsDisabled == UserDisabled {
		return User{}, core.NewWebErr("User is disabled")
	}

	if checkPassword(user.Password, user.Salt, password) {
		return user, nil
	}

	// if the password is incorrect, maybe a user_key is used instead
	ok, err := checkUserKey(rail, tx, user.Id, password)
	if err != nil {
		return User{}, err
	}
	if ok {
		return user, nil
	}

	return User{}, core.NewWebErr("Password incorrect", fmt.Sprintf("User %v login failed, password incorrect", username))
}

func checkUserKey(rail core.Rail, tx *gorm.DB, userId int, password string) (bool, error) {
	if password == "" {
		return false, nil
	}

	var id int
	t := tx.Raw(
		`SELECT id FROM user_key WHERE user_id = ? AND secret_key = ? AND expiration_time > ? AND is_del = '0' LIMIT 1`,
		userId, password, core.Now(),
	).
		Scan(&id)
	if t.Error != nil {
		rail.Errorf("failed to checkUserKey, userId: %v, %v", userId, t.Error)
	}
	return id > 0, nil
}

func checkPassword(encoded string, salt string, password string) bool {
	if password == "" {
		return false
	}
	springSalt := extractSpringSalt(encoded) // for backward compatibility (auth-service)
	ep := encodePassword(password + salt)
	provided := springSalt + ep
	return provided == encoded
}

func encodePassword(text string) string {
	sha := sha256.New()
	sha.Write([]byte(text))
	return fmt.Sprintf("%x", sha.Sum(nil))
}

// for backward compatibility, we are still using the schema used by auth-service
func extractSpringSalt(encoded string) string {
	ru := []rune(encoded)
	if len(ru) < 1 {
		return ""
	}

	if ru[0] != '{' {
		return "" // none
	}

	for i := range ru {
		if ru[i] == '}' { // end of the embedded salt
			return string(ru[0 : i+1])
		}
	}

	return "" // illegal format, or maybe none
}
