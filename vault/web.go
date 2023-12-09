package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/goauth"
	"github.com/curtisnewbie/miso/miso"
	"github.com/gin-gonic/gin"
)

const (
	headerForwardedFor = "X-Forwarded-For"
	headerUserAgent    = "User-Agent"

	passwordLoginUrl = "/user-vault/open/api/user/login"

	resCodeManageUser = "manage-users"
	resNameManageUesr = "Admin Manage Users"
	resCodeBasicUser  = "basic-user"
	resNameBasicUser  = "Basic User Operation"

	resCodeOperateLog = "operate-logs"
	resNameOperateLog = "View Operate Logs"
)

type LoginReq struct {
	Username string `json:"username" valid:"notEmpty"`
	Password string `json:"password" valid:"notEmpty"`
}

type AdminAddUserReq struct {
	Username string `json:"username" valid:"notEmpty"`
	Password string `json:"password" valid:"notEmpty"`
	RoleNo   string `json:"roleNo" valid:"notEmpty"`
}

type ListUserReq struct {
	Username   *string           `json:"username"`
	RoleNo     *string           `json:"roleNo"`
	IsDisabled *UserDisabledType `json:"isDisabled"`
	Paging     miso.Paging       `json:"pagingVo"`
}

type AdminUpdateUserReq struct {
	Id         int              `json:"id" valid:"positive"`
	RoleNo     string           `json:"roleNo" valid:"notEmpty"`
	IsDisabled UserDisabledType `json:"isDisabled"`
}

type AdminReviewUserReq struct {
	UserId       int              `json:"userId" valid:"positive"`
	ReviewStatus ReviewStatusType `json:"reviewStatus"`
}

type RegisterReq struct {
	Username string `json:"username" valid:"notEmpty"`
	Password string `json:"password" valid:"notEmpty"`
}

func registerRoutes(rail miso.Rail) error {

	goauth.ReportResourcesOnBootstrapped(rail, []goauth.AddResourceReq{
		{Code: resCodeManageUser, Name: resNameManageUesr},
		{Code: resCodeBasicUser, Name: resNameBasicUser},
		{Code: resCodeOperateLog, Name: resNameOperateLog},
	})
	goauth.ReportPathsOnBootstrapped(rail)

	miso.BaseRoute("/open/api").Group(
		miso.IPost("/user/login", UserLoginEp).
			Extra(goauth.Public("User Login (password-based)")),
		miso.IPost("/user/register/request", UserReqRegisterEp).
			Extra(goauth.Public("User request registration")),
		miso.IPost("/user/add", AddUserEp).
			Extra(goauth.Protected("Admin add user", resCodeManageUser)),
		miso.IPost("/user/list", ListUserEp).
			Extra(goauth.Protected("Admin list users", resCodeManageUser)),
		miso.IPost("/user/info/update", UpdateUserEp).
			Extra(goauth.Protected("Admin update user info", resCodeManageUser)),
		miso.IPost("/user/registration/review", ReviewUserRegistrationEp).
			Extra(goauth.Protected("Admin review user registration", resCodeManageUser)),
		miso.Get("/user/info", GetUserInfEp).
			Extra(goauth.Protected("User get user info", resCodeBasicUser)),

		// deprecated, we can just use /user/info instead
		miso.Get("/user/detail", GetUserDetailEp).
			Extra(goauth.Protected("User get user details", resCodeBasicUser)),

		miso.IPost("/user/password/update", UpdateUserEp).
			Extra(goauth.Protected("User update password", resCodeBasicUser)),

		miso.IPost("/token/exchange", ExchangeTokenEp).
			Extra(goauth.Public("Exchange token")),

		miso.Get("/token/user", GetUserTokenEp).
			Extra(goauth.Public("Get user info by token")),

		miso.IPost("/access/history", ListAccessLogEp).
			Extra(goauth.Protected("List access logs", resCodeBasicUser)),

		miso.IPost("/user/key/generate", GenUserKeyEp).
			Extra(goauth.Protected("User generate user key", resCodeBasicUser)),

		miso.IPost("/user/key/list", ListUserKeyEp).
			Extra(goauth.Protected("User list user keys", resCodeBasicUser)),

		miso.IPost("/user/key/delete", DeleteUserKeyEp).
			Extra(goauth.Protected("User delete user key", resCodeBasicUser)),
	)

	// ----------------------------------------------------------------------------------------------
	//
	// Internal endpoints
	//
	// ----------------------------------------------------------------------------------------------

	miso.BaseRoute("/remote").Group(
		miso.Get("/user/username",
			func(c *gin.Context, rail miso.Rail) (any, error) {
				id := c.Query("id")
				return FindUsername(rail, miso.GetMySQL(), id)
			},
		),

		miso.IPost("/user/info",
			func(c *gin.Context, rail miso.Rail, req ItnFindUserReq) (any, error) {
				return ItnFindUserInfo(rail, miso.GetMySQL(), req)
			},
		),

		miso.Get("/user/id",
			func(c *gin.Context, rail miso.Rail) (any, error) {
				username := c.Query("username")
				u, err := LoadUserBriefThrCache(rail, miso.GetMySQL(), username)
				if err != nil {
					return nil, err
				}
				return u.Id, nil
			},
		),

		miso.IPost("/user/userno/username",
			func(c *gin.Context, rail miso.Rail, req ItnUserNoToNameReq) (any, error) {
				return ItnFindNameOfUserNo(rail, miso.GetMySQL(), req)
			},
		),
	)
	return nil
}

func UserLoginEp(gin *gin.Context, rail miso.Rail, req LoginReq) (any, error) {
	token, user, err := UserLogin(rail, miso.GetMySQL(), PasswordLoginParam(req))
	if err != nil {
		return "", err
	}

	remoteAddr := RemoteAddr(gin.GetHeader(headerForwardedFor))
	userAgent := gin.GetHeader(headerUserAgent)

	if er := sendAccessLogEvnet(rail, AccessLogEvent{
		IpAddress:  remoteAddr,
		UserAgent:  userAgent,
		UserId:     user.Id,
		Username:   user.Username,
		Url:        passwordLoginUrl,
		AccessTime: miso.Now(),
	}); er != nil {
		rail.Errorf("Failed to sendAccessLogEvent, username: %v, remoteAddr: %v, userAgent: %v, %v",
			req.Username, remoteAddr, userAgent, er)
	}

	return token, err
}

func UserReqRegisterEp(c *gin.Context, rail miso.Rail, req RegisterReq) (any, error) {
	return nil, UserRegister(rail, miso.GetMySQL(), req)
}

func AddUserEp(c *gin.Context, rail miso.Rail, req AddUserParam) (any, error) {
	return nil, AddUser(rail, miso.GetMySQL(), AddUserParam(req), common.GetUser(rail).Username)
}

func ListUserEp(c *gin.Context, rail miso.Rail, req ListUserReq) (any, error) {
	return ListUsers(rail, miso.GetMySQL(), req)
}

func UpdateUserEp(c *gin.Context, rail miso.Rail, req AdminUpdateUserReq) (any, error) {
	return nil, AdminUpdateUser(rail, miso.GetMySQL(), req, common.GetUser(rail))
}

func ReviewUserRegistrationEp(c *gin.Context, rail miso.Rail, req AdminReviewUserReq) (any, error) {
	return nil, ReviewUserRegistration(rail, miso.GetMySQL(), req)
}

func GetUserInfEp(c *gin.Context, rail miso.Rail) (any, error) {
	timer := miso.NewPromTimer("user_vault_fetch_user_info")
	defer timer.ObserveDuration()
	u := common.GetUser(rail)
	return LoadUserBriefThrCache(rail, miso.GetMySQL(), u.Username)
}

func GetUserDetailEp(c *gin.Context, rail miso.Rail) (any, error) {
	u := common.GetUser(rail)
	return FetchUserBrief(rail, miso.GetMySQL(), u.Username)
}

func UpdatePasswordEp(c *gin.Context, rail miso.Rail, req UpdatePasswordReq) (any, error) {
	u := common.GetUser(rail)
	return nil, UpdatePassword(rail, miso.GetMySQL(), u.Username, req)
}

func ExchangeTokenEp(c *gin.Context, rail miso.Rail, req ExchangeTokenReq) (any, error) {
	timer := miso.NewPromTimer("user_vault_token_exchange")
	defer timer.ObserveDuration()
	return ExchangeToken(rail, miso.GetMySQL(), req)
}

func GetUserTokenEp(c *gin.Context, rail miso.Rail) (any, error) {
	token := c.Query("token")
	return GetTokenUser(rail, miso.GetMySQL(), token)
}

func ListAccessLogEp(c *gin.Context, rail miso.Rail, req ListAccessLogReq) (any, error) {
	return ListAccessLogs(rail, miso.GetMySQL(), common.GetUser(rail), req)
}

func GenUserKeyEp(c *gin.Context, rail miso.Rail, req GenUserKeyReq) (any, error) {
	return nil, GenUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).Username)
}

func ListUserKeyEp(c *gin.Context, rail miso.Rail, req ListUserKeysReq) (any, error) {
	return ListUserKeys(rail, miso.GetMySQL(), req, common.GetUser(rail))
}

func DeleteUserKeyEp(c *gin.Context, rail miso.Rail, req DeleteUserKeyReq) (any, error) {
	return nil, DeleteUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).UserId)
}
