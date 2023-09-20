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

	resCodeBasicUser = "basic-user"
	resNameBasicUser = "Basic User Operation"

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

	miso.IPost("/open/api/user/login",
		func(gin *gin.Context, rail miso.Rail, req LoginReq) (string, error) {
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
	)

	miso.IPost("/open/api/user/register/request",
		func(c *gin.Context, rail miso.Rail, req RegisterReq) (any, error) {
			return nil, UserRegister(rail, miso.GetMySQL(), req)
		},
		goauth.Public("User request registration"),
	)

	// ----------------------------------------------------------------------------------------------------

	miso.IPost("/open/api/user/add",
		func(c *gin.Context, rail miso.Rail, req AddUserParam) (any, error) {
			return nil, AddUser(rail, miso.GetMySQL(), AddUserParam(req), common.GetUser(rail).Username)
		},
		goauth.Protected("Admin add user", resCodeManageUser),
	)

	miso.IPost("/open/api/user/list",
		func(c *gin.Context, rail miso.Rail, req ListUserReq) (miso.PageRes[UserInfo], error) {
			return ListUsers(rail, miso.GetMySQL(), req)
		},
		goauth.Protected("Admin list users", resCodeManageUser),
	)

	miso.IPost("/open/api/user/info/update",
		func(c *gin.Context, rail miso.Rail, req AdminUpdateUserReq) (any, error) {
			return nil, AdminUpdateUser(rail, miso.GetMySQL(), req, common.GetUser(rail))
		},
		goauth.Protected("Admin update user info", resCodeManageUser),
	)

	miso.IPost("/open/api/user/registration/review",
		func(c *gin.Context, rail miso.Rail, req AdminReviewUserReq) (any, error) {
			return nil, ReviewUserRegistration(rail, miso.GetMySQL(), req)
		},
		goauth.Protected("Admin review user registration", resCodeManageUser),
	)

	miso.Get("/open/api/user/info",
		func(c *gin.Context, rail miso.Rail) (any, error) {
			u := common.GetUser(rail)
			return LoadUserBriefThrCache(rail, miso.GetMySQL(), u.Username)
		},
		goauth.Protected("User get user info", resCodeBasicUser),
	)

	// deprecated, we can just use /user/info instead
	miso.Get("/open/api/user/detail",
		func(c *gin.Context, rail miso.Rail) (any, error) {
			u := common.GetUser(rail)
			return FetchUserBrief(rail, miso.GetMySQL(), u.Username)
		},
		goauth.Protected("User get user details", resCodeBasicUser),
	)

	miso.IPost("/open/api/user/password/update",
		func(c *gin.Context, rail miso.Rail, req UpdatePasswordReq) (any, error) {
			u := common.GetUser(rail)
			return nil, UpdatePassword(rail, miso.GetMySQL(), u.Username, req)
		},
		goauth.Protected("User update password", resCodeBasicUser),
	)

	miso.IPost("/open/api/token/exchange",
		func(c *gin.Context, rail miso.Rail, req ExchangeTokenReq) (any, error) {
			return ExchangeToken(rail, miso.GetMySQL(), req)
		},
		goauth.Public("Exchange token"),
	)

	miso.Get("/open/api/token/user",
		func(c *gin.Context, rail miso.Rail) (any, error) {
			token := c.Query("token")
			return GetTokenUser(rail, miso.GetMySQL(), token)
		},
		goauth.Public("Get user info by token"),
	)

	miso.IPost("/open/api/access/history",
		func(c *gin.Context, rail miso.Rail, req ListAccessLogReq) (any, error) {
			return ListAccessLogs(rail, miso.GetMySQL(), req)
		},
		goauth.Protected("List access logs", resCodeAccessLog),
	)

	miso.IPost("/open/api/user/key/generate",
		func(c *gin.Context, rail miso.Rail, req GenUserKeyReq) (any, error) {
			return nil, GenUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).Username)
		},
		goauth.Protected("User generate user key", resCodeBasicUser),
	)

	miso.IPost("/open/api/user/key/list",
		func(c *gin.Context, rail miso.Rail, req ListUserKeysReq) (any, error) {
			return ListUserKeys(rail, miso.GetMySQL(), req, common.GetUser(rail))
		},
		goauth.Protected("User list user keys", resCodeBasicUser),
	)

	miso.IPost("/open/api/user/key/delete",
		func(c *gin.Context, rail miso.Rail, req DeleteUserKeyReq) (any, error) {
			return nil, DeleteUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).UserId)
		},
		goauth.Protected("User delete user key", resCodeBasicUser),
	)

	return nil
}
