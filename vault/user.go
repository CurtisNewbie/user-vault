package vault

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/goauth"
	"github.com/curtisnewbie/miso/miso"
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
	RoleNo   string `json:"roleNo"`
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
	CreateTime   miso.ETime
	CreateBy     string
	UpdateTime   miso.ETime
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

func loadUser(rail miso.Rail, tx *gorm.DB, username string) (User, error) {
	if username == "" {
		return User{}, miso.NewWebErr("Username is required")
	}

	var user User
	t := tx.Raw(`SELECT * FROM user WHERE username = ? and is_del = 0`, username).
		Scan(&user)

	if t.Error != nil {
		rail.Errorf("Failed to find user, username: %v, %v", username, t.Error)
		return User{}, t.Error
	}

	if t.RowsAffected < 1 {
		return User{}, miso.NewWebErr("User not found", fmt.Sprintf("User %v is not found", username))
	}

	return user, nil
}

func UserLogin(rail miso.Rail, tx *gorm.DB, req PasswordLoginParam) (string, error) {
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

	return miso.JwtEncode(claims, exp)
}

func userLogin(rail miso.Rail, tx *gorm.DB, username string, password string) (User, error) {
	if miso.IsBlankStr(username) {
		return User{}, miso.NewWebErr("Username is required")
	}

	if miso.IsBlankStr(password) {
		return User{}, miso.NewWebErr("Password is required")
	}

	user, err := loadUser(rail, tx, username)
	if err != nil {
		return User{}, err
	}

	if user.ReviewStatus == ReviewPending {
		return User{}, miso.NewWebErr("Your Registration is being reviewed, please wait for approval")
	}

	if user.ReviewStatus == ReviewRejected {
		return User{}, miso.NewWebErr("Your are not permitted to login, please contact administrator")
	}

	if user.IsDisabled == UserDisabled {
		return User{}, miso.NewWebErr("User is disabled")
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

	return User{}, miso.NewWebErr("Password incorrect", "User %v login failed, password incorrect", username)
}

func checkUserKey(rail miso.Rail, tx *gorm.DB, userId int, password string) (bool, error) {
	if password == "" {
		return false, nil
	}

	var id int
	t := tx.Raw(
		`SELECT id FROM user_key WHERE user_id = ? AND secret_key = ? AND expiration_time > ? AND is_del = '0' LIMIT 1`,
		userId, password, miso.Now(),
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

func getRoleName(rail miso.Rail, roleNo string) (string, error) {
	r, err := getRoleInfo(rail, roleNo)
	if err != nil {
		return "", err
	}
	return r.Name, nil
}

func getRoleInfo(rail miso.Rail, roleNo string) (*goauth.RoleInfoResp, error) {
	resp, err := goauth.GetRoleInfo(rail, goauth.RoleInfoReq{
		RoleNo: roleNo,
	})
	if err != nil {
		rail.Errorf("Failed to goauth.GetRoleInfo, roleNo: %v, %v", roleNo, err)
		return nil, err
	}

	if resp == nil {
		return nil, miso.NewWebErr("Role not found", "Role %v is not found", roleNo)
	}
	return resp, nil
}

func checkNewUsername(username string) error {
	if !usernameRegexp.MatchString(username) {
		return miso.NewWebErr("Username must have 6-50 characters, permitted characters include: 'a-z A-Z 0-9 . - _ @'",
			"Actual username: %v", username)
	}
	return nil
}

func checkNewPassword(password string) error {
	len := len([]rune(password))
	if len < passwordMinLen {
		return miso.NewWebErr(fmt.Sprintf("Password must have at least %v characters", passwordMinLen),
			"Actual length: %v", len)
	}
	return nil
}

func AddUser(rail miso.Rail, tx *gorm.DB, req AddUserParam, operator string) error {
	if req.RoleNo != "" {
		_, err := getRoleInfo(rail, req.RoleNo)
		if err != nil {
			return err
		}
	}

	if e := checkNewUsername(req.Username); e != nil {
		return e
	}

	if e := checkNewPassword(req.Password); e != nil {
		return e
	}

	if len([]rune(req.Password)) < passwordMinLen {
		return miso.NewWebErr(fmt.Sprintf("Password must have at least %v characters", passwordMinLen))
	}

	if req.Username == req.Password {
		return miso.NewWebErr("Username and password must be different")
	}

	if _, err := loadUser(rail, tx, req.Username); err == nil {
		return miso.NewWebErr("User is already registered")
	}

	user := prepUserCred(req.Password)
	user.UserNo = miso.GenIdP("UE")
	user.Username = req.Username
	user.Role = ""
	user.RoleNo = req.RoleNo
	user.CreateBy = operator
	user.CreateTime = miso.Now()
	user.IsDisabled = UserNormal
	user.ReviewStatus = ReviewApproved

	err := tx.Table("user").
		Create(&user).
		Error

	if err != nil {
		rail.Errorf("failed to add new user '%v', %v", req.Username, err)
		return err
	}

	rail.Infof("New user '%v' with roleNo: %v is added by %v", req.Username, req.RoleNo, operator)
	return nil
}

func prepUserCred(pwd string) User {
	u := User{}
	u.Salt = miso.RandStr(6)
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
	CreateTime miso.ETime       `json:"createTime"`
	CreateBy   string           `json:"createBy"`
	UpdateTime miso.ETime       `json:"updateTime"`
	UpdateBy   string           `json:"updateBy"`
	IsDel      common.IS_DEL    `json:"isDel"`
}

func ListUsers(rail miso.Rail, tx *gorm.DB, req ListUserReq) (miso.PageRes[UserInfo], error) {
	roleInfoCache := miso.LocalCache[string]{}

	qpm := miso.QueryPageParam[ListUserReq, UserInfo]{
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
	return miso.QueryPage[ListUserReq, UserInfo](rail, tx, qpm)
}

func AdminUpdateUser(rail miso.Rail, tx *gorm.DB, req AdminUpdateUserReq, operator common.User) error {
	if operator.UserId == req.Id {
		return miso.NewWebErr("You cannot update yourself")
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

func ReviewUserRegistration(rail miso.Rail, tx *gorm.DB, req AdminReviewUserReq) error {
	if req.ReviewStatus != ReviewRejected && req.ReviewStatus != ReviewApproved {
		return miso.NewWebErr("Illegal Argument", "ReviewStatus was neither ReviewApproved nor ReviewRejected, it was %v",
			req.ReviewStatus)
	}

	return miso.RLockExec(rail, fmt.Sprintf("auth:user:registration:review:%v", req.UserId),
		func() error {
			var user User
			t := tx.Raw(`SELECT * FROM user WHERE id = ?`, req.UserId).
				Scan(&user)
			if t.Error != nil {
				rail.Errorf("Failed to find user, id = %v %v", req.UserId, t.Error)
				return t.Error
			}

			if t.RowsAffected < 1 {
				return miso.NewWebErr("User not found", "User %v not found", req.UserId)
			}

			if user.IsDel == common.IS_DEL_Y {
				return miso.NewWebErr("User not found", "User %v is deleted", req.UserId)
			}

			if user.ReviewStatus != ReviewPending {
				return miso.NewWebErr("User's registration has already been reviewed")
			}

			isDisabled := UserDisabled
			if req.ReviewStatus == ReviewApproved {
				isDisabled = UserNormal
			}

			err := tx.Exec(`UPDATE user SET review_status = ?, is_disabled = ? WHERE id = ?`, req.ReviewStatus, isDisabled, req.UserId).
				Error

			if err != nil {
				rail.Errorf("failed to update user for registration review, userId: %v, %v", req.UserId, err)
			}
			return err
		},
	)
}

func UserRegister(rail miso.Rail, tx *gorm.DB, req RegisterReq) error {
	return AddUser(rail, tx, AddUserParam{
		Username: req.Username,
		Password: req.Password,
	}, "")
}

type UserInfoBrief struct {
	Id       int    `json:"id"`
	Username string `json:"username"`
	RoleName string `json:"roleName"`
	RoleNo   string `json:"roleNo"`
	UserNo   string `json:"userNo"`
}

func LoadUserInfoBrief(rail miso.Rail, tx *gorm.DB, username string) (UserInfoBrief, error) {
	u, err := loadUser(rail, tx, username)
	if err != nil {
		return UserInfoBrief{}, err
	}

	roleName := ""
	if r, err := getRoleName(rail, u.RoleNo); err == nil {
		roleName = r
	}

	return UserInfoBrief{
		Id:       u.Id,
		Username: u.Username,
		RoleName: roleName,
		RoleNo:   u.RoleNo,
		UserNo:   u.UserNo,
	}, nil
}
