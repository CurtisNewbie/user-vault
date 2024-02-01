package vault

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/goauth"
	"github.com/curtisnewbie/miso/miso"
	"github.com/curtisnewbie/user-vault/api"
	"gorm.io/gorm"
)

var (
	usernameRegexp = regexp.MustCompile(`^[a-zA-Z0-9_\-@.]{6,50}$`)
	passwordMinLen = 8

	userInfoCache = miso.NewRCache[UserDetail]("user-vault:user:info", miso.RCacheConfig{Exp: time.Hour * 1})
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

type User struct {
	Id           int
	UserNo       string
	Username     string
	Password     string
	Salt         string
	ReviewStatus string
	RoleNo       string
	IsDisabled   int
	CreateTime   miso.ETime
	CreateBy     string
	UpdateTime   miso.ETime
	UpdateBy     string
	IsDel        common.IS_DEL
}

func (u *User) Deleted() bool {
	return u.IsDel == common.IS_DEL_Y
}

func (u *User) CanReview() bool {
	return u.ReviewStatus == api.ReviewPending
}

type UserDetail struct {
	Id           int    `json:"id"`
	Username     string `json:"username"`
	RoleName     string `json:"roleName"`
	RoleNo       string `json:"roleNo"`
	UserNo       string `json:"userNo"`
	RegisterDate string `json:"registerDate"`
	Password     string `json:"password"`
	Salt         string `json:"salt"`
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
		return User{}, miso.NewErr("Username is required")
	}

	var user User
	t := tx.Raw(`SELECT * FROM user WHERE username = ? and is_del = 0`, username).
		Scan(&user)

	if t.Error != nil {
		rail.Errorf("Failed to find user, username: %v, %v", username, t.Error)
		return User{}, t.Error
	}

	if t.RowsAffected < 1 {
		return User{}, miso.NewErr("User not found", fmt.Sprintf("User %v is not found", username))
	}

	return user, nil
}

func UserLogin(rail miso.Rail, tx *gorm.DB, req PasswordLoginParam) (string, User, error) {
	user, err := userLogin(rail, tx, req.Username, req.Password)
	if err != nil {
		return "", User{}, err
	}

	tu := TokenUser{
		Id:       user.Id,
		UserNo:   user.UserNo,
		Username: user.Username,
		RoleNo:   user.RoleNo,
	}

	rail.Debugf("buildToken %+v", tu)
	tkn, err := buildToken(tu, 15*time.Minute)
	if err != nil {
		return "", User{}, err
	}
	return tkn, user, nil
}

type TokenUser struct {
	Id       int
	UserNo   string
	Username string
	RoleNo   string
}

func buildToken(user TokenUser, exp time.Duration) (string, error) {
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
		return User{}, miso.NewErr("Username is required")
	}

	if miso.IsBlankStr(password) {
		return User{}, miso.NewErr("Password is required")
	}

	user, err := loadUser(rail, tx, username)
	if err != nil {
		return User{}, err
	}

	if user.ReviewStatus == api.ReviewPending {
		return User{}, miso.NewErr("Your Registration is being reviewed, please wait for approval")
	}

	if user.ReviewStatus == api.ReviewRejected {
		return User{}, miso.NewErr("Your are not permitted to login, please contact administrator")
	}

	if user.IsDisabled == api.UserDisabled {
		return User{}, miso.NewErr("User is disabled")
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

	return User{}, miso.NewErr("Password incorrect", "User %v login failed, password incorrect", username)
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
		return nil, miso.NewErr("Role not found", "Role %v is not found", roleNo)
	}
	return resp, nil
}

func checkNewUsername(username string) error {
	if !usernameRegexp.MatchString(username) {
		return miso.NewErr("Username must have 6-50 characters, permitted characters include: 'a-z A-Z 0-9 . - _ @'",
			"Actual username: %v", username)
	}
	return nil
}

func checkNewPassword(password string) error {
	len := len([]rune(password))
	if len < passwordMinLen {
		return miso.NewErr(fmt.Sprintf("Password must have at least %v characters", passwordMinLen),
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

	if req.Username == req.Password {
		return miso.NewErr("Username and password must be different")
	}

	if _, err := loadUser(rail, tx, req.Username); err == nil {
		return miso.NewErr("User is already registered")
	}

	user := prepUserCred(req.Password)
	user.UserNo = miso.GenIdP("UE")
	user.Username = req.Username
	user.RoleNo = req.RoleNo
	user.CreateBy = operator
	user.CreateTime = miso.Now()
	user.IsDisabled = api.UserNormal
	user.ReviewStatus = api.ReviewApproved

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

func ListUsers(rail miso.Rail, tx *gorm.DB, req ListUserReq) (miso.PageRes[api.UserInfo], error) {
	roleInfoCache := miso.LocalCache[string]{}

	qpp := miso.QueryPageParam[api.UserInfo]{
		ReqPage: req.Paging,
		AddSelectQuery: func(tx *gorm.DB) *gorm.DB {
			return tx.Select("*")
		},
		ApplyConditions: func(tx *gorm.DB) *gorm.DB {
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
		ForEach: func(ui api.UserInfo) api.UserInfo {
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
	return qpp.ExecPageQuery(rail, tx)
}

func AdminUpdateUser(rail miso.Rail, tx *gorm.DB, req AdminUpdateUserReq, operator common.User) error {
	if operator.UserId == req.Id {
		return miso.NewErr("You cannot update yourself")
	}

	_, err := getRoleInfo(rail, req.RoleNo)
	if err != nil {
		return miso.NewErr("Invalid role", "failed to get role info, roleNo may be invalid, %v", err)
	}

	return tx.Exec(
		`UPDATE user SET is_disabled = ?, update_by = ?, role_no = ? WHERE id = ?`,
		req.IsDisabled, operator.Username, req.RoleNo, req.Id,
	).Error
}

func ReviewUserRegistration(rail miso.Rail, tx *gorm.DB, req AdminReviewUserReq) error {
	if req.ReviewStatus != api.ReviewRejected && req.ReviewStatus != api.ReviewApproved {
		return miso.NewErr("Illegal Argument", "ReviewStatus was neither ReviewApproved nor ReviewRejected, it was %v",
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
				return miso.NewErr("User not found", "User %v not found", req.UserId)
			}

			if user.Deleted() {
				return miso.NewErr("User not found", "User %v is deleted", req.UserId)
			}

			if !user.CanReview() {
				return miso.NewErr("User's registration has already been reviewed")
			}

			isDisabled := api.UserDisabled
			if req.ReviewStatus == api.ReviewApproved {
				isDisabled = api.UserNormal
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
	Id           int    `json:"id"`
	Username     string `json:"username"`
	RoleName     string `json:"roleName"`
	RoleNo       string `json:"roleNo"`
	UserNo       string `json:"userNo"`
	RegisterDate string `json:"registerDate"`
}

func FetchUserBrief(rail miso.Rail, tx *gorm.DB, username string) (UserInfoBrief, error) {
	ud, err := LoadUserBriefThrCache(rail, miso.GetMySQL(), username)
	if err != nil {
		return UserInfoBrief{}, err
	}
	return UserInfoBrief{
		Id:           ud.Id,
		Username:     ud.Username,
		RoleName:     ud.RoleName,
		RoleNo:       ud.RoleNo,
		UserNo:       ud.UserNo,
		RegisterDate: ud.RegisterDate,
	}, nil
}

func LoadUserBriefThrCache(rail miso.Rail, tx *gorm.DB, username string) (UserDetail, error) {
	rail.Debugf("LoadUserBriefThrCache, username: %v", username)
	return userInfoCache.Get(rail, username, func(rail miso.Rail, username string) (UserDetail, error) {
		rail.Debugf("LoadUserInfoBrief, username: %v", username)
		return LoadUserInfoBrief(rail, miso.GetMySQL(), username)
	})
}

func InvalidateUserInfoCache(rail miso.Rail, username string) error {
	return userInfoCache.Del(rail, username)
}

func LoadUserInfoBrief(rail miso.Rail, tx *gorm.DB, username string) (UserDetail, error) {
	u, err := loadUser(rail, tx, username)
	if err != nil {
		return UserDetail{}, err
	}

	roleName, err := getRoleName(rail, u.RoleNo)
	if err != nil {
		return UserDetail{}, fmt.Errorf("failed to getRoleName, roleNo: %v, %v", u.RoleNo, err)
	}

	return UserDetail{
		Id:           u.Id,
		Username:     u.Username,
		RoleName:     roleName,
		RoleNo:       u.RoleNo,
		UserNo:       u.UserNo,
		RegisterDate: u.CreateTime.FormatClassic(),
		Salt:         u.Salt,
		Password:     u.Password,
	}, nil
}

type UpdatePasswordReq struct {
	PrevPassword string `json:"prevPassword" valid:"notEmpty"`
	NewPassword  string `json:"newPassword" valid:"notEmpty"`
}

func UpdatePassword(rail miso.Rail, tx *gorm.DB, username string, req UpdatePasswordReq) error {
	req.NewPassword = strings.TrimSpace(req.NewPassword)
	req.PrevPassword = strings.TrimSpace(req.PrevPassword)

	if req.NewPassword == req.PrevPassword {
		return miso.NewErr("New password must be different")
	}

	if err := checkNewPassword(req.NewPassword); err != nil {
		return err
	}

	if username == req.NewPassword {
		return miso.NewErr("Username and password must be different")
	}

	u, err := LoadUserBriefThrCache(rail, tx, username)
	if err != nil {
		return miso.NewErr("Failed to load user info, please try again later", "Failed to LoadUserBriefThrCache, %v", err)
	}

	if !checkPassword(u.Password, u.Salt, req.PrevPassword) {
		return miso.NewErr("Password incorrect")
	}

	t := tx.Exec("update user set password = ? where username = ?", encodePasswordSalt(req.NewPassword, u.Salt), username)
	if t.Error != nil {
		return miso.NewErr("Failed to update password, please try again laster", "Failed to update password, %v", t.Error)
	}
	return nil
}

type ExchangeTokenReq struct {
	Token string `json:"token" valid:"notEmpty"`
}

func DecodeTokenUser(rail miso.Rail, token string) (TokenUser, error) {
	tu := TokenUser{}
	decoded, err := miso.JwtDecode(token)
	if err != nil || !decoded.Valid {
		return TokenUser{}, miso.NewErr("Illegal token", "Failed to decode jwt token, %v", err)
	}

	tu.Id, err = strconv.Atoi(fmt.Sprintf("%v", decoded.Claims["id"]))
	if err != nil {
		return tu, err
	}
	tu.Username = decoded.Claims["username"].(string)
	tu.UserNo = decoded.Claims["userno"].(string)
	tu.RoleNo = decoded.Claims["roleno"].(string)
	return tu, nil
}

func DecodeTokenUsername(rail miso.Rail, token string) (string, error) {
	decoded, err := miso.JwtDecode(token)
	if err != nil || !decoded.Valid {
		return "", miso.NewErr("Illegal token", "Failed to decode jwt token, %v", err)
	}
	username := decoded.Claims["username"]
	un, ok := username.(string)
	if !ok {
		un = fmt.Sprintf("%v", username)
	}
	return un, nil
}

func ExchangeToken(rail miso.Rail, tx *gorm.DB, req ExchangeTokenReq) (string, error) {
	u, err := DecodeTokenUser(rail, req.Token)
	if err != nil {
		return "", err
	}

	tu := TokenUser{
		Id:       u.Id,
		UserNo:   u.UserNo,
		Username: u.Username,
		RoleNo:   u.RoleNo,
	}

	rail.Debugf("buildToken %+v", tu)
	return buildToken(tu, 15*time.Minute)
}

func GetTokenUser(rail miso.Rail, tx *gorm.DB, token string) (UserInfoBrief, error) {
	if miso.IsBlankStr(token) {
		return UserInfoBrief{}, miso.NewErr("Invalid token", "Token is blank")
	}
	username, err := DecodeTokenUsername(rail, token)
	if err != nil {
		return UserInfoBrief{}, err
	}

	u, err := LoadUserBriefThrCache(rail, tx, username)

	if err != nil {
		return UserInfoBrief{}, err
	}
	return UserInfoBrief{
		Id:           u.Id,
		Username:     u.Username,
		RoleName:     u.RoleName,
		RoleNo:       u.RoleNo,
		UserNo:       u.UserNo,
		RegisterDate: u.RegisterDate,
	}, nil
}

func FindUsername(rail miso.Rail, tx *gorm.DB, username string) (string, error) {
	return "", nil
}

func ItnFindUserInfo(rail miso.Rail, tx *gorm.DB, req api.FindUserReq) (api.UserInfo, error) {

	var ui api.UserInfo
	tx = tx.Table("user")

	if req.UserId != nil {
		return ui, tx.Where("id = ?", *req.UserId).Scan(&ui).Error
	}
	if req.UserNo != nil {
		return ui, tx.Where("user_no = ?", *req.UserNo).Scan(&ui).Error
	}
	if req.Username != nil {
		return ui, tx.Where("username = ?", *req.Username).Scan(&ui).Error
	}

	return ui, miso.NewErr("Must provide at least one parameter")
}

func ItnFindNameOfUserNo(rail miso.Rail, tx *gorm.DB, req api.FetchUsernameReq) (api.FetchUsernamesRes, error) {
	if len(req.UserNos) < 1 {
		return api.FetchUsernamesRes{UserNoToUsername: map[string]string{}}, nil
	}

	type UserNoToName struct {
		UserNo   string
		Username string
	}

	var queried []UserNoToName
	err := tx.Table("user").
		Select("username", "user_no").
		Where("user_no in ?", miso.Distinct(req.UserNos)).
		Scan(&queried).
		Error
	if err != nil {
		return api.FetchUsernamesRes{}, err
	}

	mapping := miso.StrMap(queried,
		func(un UserNoToName) string {
			return un.UserNo
		},
		func(un UserNoToName) string {
			return un.Username
		},
	)
	return api.FetchUsernamesRes{UserNoToUsername: mapping}, nil
}
