package vault

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/goauth"
	"github.com/curtisnewbie/miso/core"
	"github.com/curtisnewbie/miso/jwt"
	"github.com/curtisnewbie/miso/mysql"
	"gorm.io/gorm"
)

const (
	ReviewPending  ReviewStatusType = "PENDING"
	ReviewRejected ReviewStatusType = "REJECTED"
	ReviewApproved ReviewStatusType = "APPROVED"

	UserNormal   UserDisabledType = 0
	UserDisabled UserDisabledType = 1
)

var (
	usernameRegexp = regexp.MustCompile(`^[a-zA-Z0-9_\-@.]{6,50}$`)
	passwordMinLen = 8
)

type PasswordLoginParam struct {
	Username string
	Password string
}

type AddUserParam struct {
	Username string `json:"username" valid:"notEmpty"`
	Password string `json:"password" valid:"notEmpty"`
	RoleNo   string `json:"roleNo" valid:"notEmpty"`
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
	Role         string // TODO: remove this
	RoleNo       string
	IsDisabled   UserDisabledType
	CreateTime   core.ETime
	CreateBy     string
	UpdateTime   core.ETime
	UpdateBy     string
	IsDel        common.IS_DEL
}

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

func UserLogin(rail core.Rail, tx *gorm.DB, req PasswordLoginParam) (string, error) {
	user, err := userLogin(rail, tx, req.Username, req.Password)
	if err != nil {
		return "", err
	}
	return buildToken(user, 15*time.Minute)
}

func buildToken(user User, exp time.Duration) (string, error) {
	claims := map[string]any{
		"id":       user.Id,
		"username": user.Username,
		"userno":   user.UserNo,
		"roleno":   user.RoleNo,
	}

	return jwt.EncodeToken(claims, exp)
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

	return User{}, core.NewInterErr("Password incorrect", "User %v login failed, password incorrect", username)
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
	ep := encodePasswordSalt(password, salt)
	provided := springSalt + ep
	return provided == encoded
}

func encodePasswordSalt(pwd string, salt string) string {
	return encodePassword(pwd + salt)
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

func getRoleInfo(rail core.Rail, roleNo string) (*goauth.RoleInfoResp, error) {
	resp, err := goauth.GetRoleInfo(rail, goauth.RoleInfoReq{
		RoleNo: roleNo,
	})
	if err != nil {
		rail.Errorf("Failed to goauth.GetRoleInfo, roleNo: %v, %v", roleNo, err)
		return nil, err
	}

	if resp == nil {
		return nil, core.NewInterErr("Role not found", "Role %v is not found", roleNo)
	}
	return resp, nil
}

func AdminAddUser(rail core.Rail, tx *gorm.DB, req AddUserParam, operator common.User) error {
	_, err := getRoleInfo(rail, req.RoleNo)
	if err != nil {
		return err
	}

	if !usernameRegexp.MatchString(req.Username) {
		return core.NewWebErr("Username must have 6-50 characters, permitted characters include: 'a-z A-Z 0-9 . - _ @'")
	}

	if len([]rune(req.Password)) < passwordMinLen {
		return core.NewWebErr(fmt.Sprintf("Password must have at least %v characters", passwordMinLen))
	}

	if req.Username == req.Password {
		return core.NewWebErr("Username and password must be different")
	}

	if _, err := loadUser(rail, tx, req.Username); err == nil {
		return core.NewWebErr("User is already registered")
	}

	user := prepUserCred(req.Password)
	user.UserNo = core.GenIdP("UE")
	user.Username = req.Username
	user.Role = ""
	user.RoleNo = req.RoleNo
	user.CreateBy = operator.Username
	user.CreateTime = core.Now()
	user.IsDisabled = UserNormal
	user.ReviewStatus = ReviewApproved

	err = tx.Table("user").
		Create(&user).
		Error

	if err != nil {
		rail.Errorf("failed to add new user '%v', %v", req.Username, err)
		return err
	}

	rail.Infof("New user '%v' with roleNo: %v is added by %v", req.Username, req.RoleNo, operator.Username)
	return nil
}

func prepUserCred(pwd string) User {
	u := User{}
	u.Salt = core.RandStr(6)
	u.Password = encodePasswordSalt(pwd, u.Salt)
	return u
}

type UserInfo struct {
	Id         int              `json:"id"`
	Username   string           `json:"username"`
	RoleName   string           `json:"roleName"`
	RoleNo     string           `json:"roleNo"`
	UserNo     string           `json:"userNo"`
	IsDisabled UserDisabledType `json:"isDisabled"`
	CreateTime core.ETime       `json:"createTime"`
	CreateBy   string           `json:"createBy"`
	UpdateTime core.ETime       `json:"updateTime"`
	UpdateBy   string           `json:"updateBy"`
	IsDel      common.IS_DEL    `json:"isDel"`
}

func ListUsers(rail core.Rail, tx *gorm.DB, req ListUserReq) (mysql.PageRes[UserInfo], error) {
	roleInfoCache := core.LocalCache[string]{}

	qpm := mysql.QueryPageParam[ListUserReq, UserInfo]{
		Req:     req,
		ReqPage: req.Paging,
		AddSelectQuery: func(tx *gorm.DB) *gorm.DB {
			return tx.Select("*")
		},
		ApplyConditions: func(tx *gorm.DB, req ListUserReq) *gorm.DB {
			if req.RoleNo != nil && *req.RoleNo != "" {
				tx = tx.Where("role_no = ?", *req.RoleNo)
			}
			if req.Username != nil && *req.Username != "" {
				tx = tx.Where("username LIKE ?", "%"+*req.Username+"%")
			}
			if req.IsDisabled != nil {
				tx = tx.Where("is_disabled = ?", *req.IsDisabled)
			}
			return tx.Where("is_del = 0")
		},
		GetBaseQuery: func(tx *gorm.DB) *gorm.DB {
			return tx.Table("user")
		},
		ForEach: func(ui UserInfo) UserInfo {
			if ui.RoleNo == "" {
				return ui
			}

			name, err := roleInfoCache.Get(ui.RoleNo, func(s string) (string, error) {
				resp, err := goauth.GetRoleInfo(rail, goauth.RoleInfoReq{
					RoleNo: ui.RoleNo,
				})
				if err != nil || resp == nil {
					rail.Errorf("Failed to goauth.GetRoleInfo, roleNo: %v, %v", req.RoleNo, err)
					return "", err
				}
				return resp.Name, nil
			})

			if err == nil {
				ui.RoleName = name
			}

			return ui
		},
	}
	return mysql.QueryPage[ListUserReq, UserInfo](rail, tx, qpm)
}

func AdminUpdateUser(rail core.Rail, tx *gorm.DB, req AdminUpdateUserReq, operator common.User) error {
	if operator.UserId == req.Id {
		return core.NewWebErr("You cannot update yourself")
	}

	_, err := getRoleInfo(rail, req.RoleNo)
	if err != nil {
		return err
	}

	return tx.Exec(
		`UPDATE user SET is_disabled = ?, update_by = ?, role_no = ? WHERE id = ?`,
		req.IsDisabled, operator.Username, req.RoleNo, req.Id,
	).Error
}
