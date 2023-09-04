package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/goauth"
	"github.com/curtisnewbie/miso/core"
	"github.com/curtisnewbie/miso/mysql"
	"github.com/curtisnewbie/miso/server"
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
	Paging     core.Paging       `json:"pagingVo"`
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

func registerRoutes(rail core.Rail) error {

	goauth.ReportResourcesOnBootstrapped(rail, []goauth.AddResourceReq{
		{Code: resCodeManageUser, Name: resNameManageUesr},
		{Code: resCodeBasicUser, Name: resNameBasicUser},
		{Code: resCodeAccessLog, Name: resNameAccessLog},
		{Code: resCodeOperateLog, Name: resNameOperateLog},
	})
	goauth.ReportPathsOnBootstrapped(rail)

	server.IPost("/open/api/user/login",
		func(gin *gin.Context, rail core.Rail, req LoginReq) (string, error) {
			token, err := UserLogin(rail, mysql.GetConn(), PasswordLoginParam(req))
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
				AccessTime: core.Now(),
			}); er != nil {
				rail.Errorf("Failed to sendAccessLogEvent, username: %v, remoteAddr: %v, userAgent: %v, %v",
					req.Username, remoteAddr, userAgent, er)
			}

			return token, err
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "User Login (password-based)", Type: goauth.PT_PUBLIC}),
	)

	server.IPost("/open/api/user/register/request",
		func(c *gin.Context, rail core.Rail, req RegisterReq) (any, error) {
			return nil, UserRegister(rail, mysql.GetConn(), req)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "User request registration", Type: goauth.PT_PUBLIC}),
	)

	// ----------------------------------------------------------------------------------------------------

	server.IPost("/open/api/user/add",
		func(c *gin.Context, rail core.Rail, req AddUserParam) (any, error) {
			return nil, AddUser(rail, mysql.GetConn(), AddUserParam(req), common.GetUser(rail).Username)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Admin add user", Code: resCodeManageUser, Type: goauth.PT_PROTECTED}),
	)

	server.IPost("/open/api/user/list",
		func(c *gin.Context, rail core.Rail, req ListUserReq) (mysql.PageRes[UserInfo], error) {
			return ListUsers(rail, mysql.GetConn(), req)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Admin list users", Code: resCodeManageUser, Type: goauth.PT_PROTECTED}),
	)

	server.IPost("/open/api/user/info/update",
		func(c *gin.Context, rail core.Rail, req AdminUpdateUserReq) (any, error) {
			return nil, AdminUpdateUser(rail, mysql.GetConn(), req, common.GetUser(rail))
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Admin update user info", Code: resCodeManageUser, Type: goauth.PT_PROTECTED}),
	)

	server.IPost("/open/api/user/registration/review",
		func(c *gin.Context, rail core.Rail, req AdminReviewUserReq) (any, error) {
			return nil, ReviewUserRegistration(rail, mysql.GetConn(), req)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Admin review user registration", Code: resCodeManageUser, Type: goauth.PT_PROTECTED}),
	)

	server.Get("/open/api/user/info",
		func(c *gin.Context, rail core.Rail) (any, error) {
			u := common.GetUser(rail)
			return LoadUserInfoBrief(rail, mysql.GetConn(), u.Username)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "User get user info", Code: resCodeBasicUser, Type: goauth.PT_PROTECTED}),
	)

	return nil
}
