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

	resCodeAccessLog = "access-logs"
	resNameAccessLog = "View Access Logs"

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
		{Code: resCodeAccessLog, Name: resNameAccessLog},
		{Code: resCodeOperateLog, Name: resNameOperateLog},
	})
	goauth.ReportPathsOnBootstrapped(rail)

	miso.BaseRoute("/open/api").Group(
		miso.IPost("/user/login",
			func(gin *gin.Context, rail miso.Rail, req LoginReq) (any, error) {
				token, err := UserLogin(rail, miso.GetMySQL(), PasswordLoginParam(req))
				if err != nil {
					return "", err
				}

				remoteAddr := RemoteAddr(gin.GetHeader(headerForwardedFor))
				userAgent := gin.GetHeader(headerUserAgent)

				if er := sendAccessLogEvnet(rail, AccessLogEvent{
					IpAddress:  remoteAddr,
					UserAgent:  userAgent,
					UserId:     0, // TODO: remove this field
					Username:   req.Username,
					Url:        passwordLoginUrl,
					AccessTime: miso.Now(),
				}); er != nil {
					rail.Errorf("Failed to sendAccessLogEvent, username: %v, remoteAddr: %v, userAgent: %v, %v",
						req.Username, remoteAddr, userAgent, er)
				}

				return token, err
			},
			goauth.Public("User Login (password-based)"),
		),
		miso.IPost("/user/register/request",
			func(c *gin.Context, rail miso.Rail, req RegisterReq) (any, error) {
				return nil, UserRegister(rail, miso.GetMySQL(), req)
			},
			goauth.Public("User request registration"),
		),

		miso.IPost("/user/add",
			func(c *gin.Context, rail miso.Rail, req AddUserParam) (any, error) {
				return nil, AddUser(rail, miso.GetMySQL(), AddUserParam(req), common.GetUser(rail).Username)
			},
			goauth.Protected("Admin add user", resCodeManageUser),
		),

		miso.IPost("/user/list",
			func(c *gin.Context, rail miso.Rail, req ListUserReq) (any, error) {
				return ListUsers(rail, miso.GetMySQL(), req)
			},
			goauth.Protected("Admin list users", resCodeManageUser),
		),

		miso.IPost("/user/info/update",
			func(c *gin.Context, rail miso.Rail, req AdminUpdateUserReq) (any, error) {
				return nil, AdminUpdateUser(rail, miso.GetMySQL(), req, common.GetUser(rail))
			},
			goauth.Protected("Admin update user info", resCodeManageUser),
		),

		miso.IPost("/user/registration/review",
			func(c *gin.Context, rail miso.Rail, req AdminReviewUserReq) (any, error) {
				return nil, ReviewUserRegistration(rail, miso.GetMySQL(), req)
			},
			goauth.Protected("Admin review user registration", resCodeManageUser),
		),

		miso.Get("/user/info",
			func(c *gin.Context, rail miso.Rail) (any, error) {
				timer := miso.NewPromTimer("user_vault_fetch_user_info")
				defer timer.ObserveDuration()
				u := common.GetUser(rail)
				return LoadUserBriefThrCache(rail, miso.GetMySQL(), u.Username)
			},
			goauth.Protected("User get user info", resCodeBasicUser),
		),

		// deprecated, we can just use /user/info instead
		miso.Get("/user/detail",
			func(c *gin.Context, rail miso.Rail) (any, error) {
				u := common.GetUser(rail)
				return FetchUserBrief(rail, miso.GetMySQL(), u.Username)
			},
			goauth.Protected("User get user details", resCodeBasicUser),
		),

		miso.IPost("/user/password/update",
			func(c *gin.Context, rail miso.Rail, req UpdatePasswordReq) (any, error) {
				u := common.GetUser(rail)
				return nil, UpdatePassword(rail, miso.GetMySQL(), u.Username, req)
			},
			goauth.Protected("User update password", resCodeBasicUser),
		),

		miso.IPost("/token/exchange",
			func(c *gin.Context, rail miso.Rail, req ExchangeTokenReq) (any, error) {
				timer := miso.NewPromTimer("user_vault_token_exchange")
				defer timer.ObserveDuration()
				return ExchangeToken(rail, miso.GetMySQL(), req)
			},
			goauth.Public("Exchange token"),
		),

		miso.Get("/token/user",
			func(c *gin.Context, rail miso.Rail) (any, error) {
				token := c.Query("token")
				return GetTokenUser(rail, miso.GetMySQL(), token)
			},
			goauth.Public("Get user info by token"),
		),

		miso.IPost("/access/history",
			func(c *gin.Context, rail miso.Rail, req ListAccessLogReq) (any, error) {
				return ListAccessLogs(rail, miso.GetMySQL(), req)
			},
			goauth.Protected("List access logs", resCodeAccessLog),
		),

		miso.IPost("/user/key/generate",
			func(c *gin.Context, rail miso.Rail, req GenUserKeyReq) (any, error) {
				return nil, GenUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).Username)
			},
			goauth.Protected("User generate user key", resCodeBasicUser),
		),

		miso.IPost("/user/key/list",
			func(c *gin.Context, rail miso.Rail, req ListUserKeysReq) (any, error) {
				return ListUserKeys(rail, miso.GetMySQL(), req, common.GetUser(rail))
			},
			goauth.Protected("User list user keys", resCodeBasicUser),
		),

		miso.IPost("/user/key/delete",
			func(c *gin.Context, rail miso.Rail, req DeleteUserKeyReq) (any, error) {
				return nil, DeleteUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).UserId)
			},
			goauth.Protected("User delete user key", resCodeBasicUser),
		),
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
