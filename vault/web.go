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
		goauth.PathDocExtra(goauth.PathDoc{Desc: "User Login (password-based)", Type: goauth.PT_PUBLIC}),
	)

	miso.IPost("/open/api/user/register/request",
		func(c *gin.Context, rail miso.Rail, req RegisterReq) (any, error) {
			return nil, UserRegister(rail, miso.GetMySQL(), req)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "User request registration", Type: goauth.PT_PUBLIC}),
	)

	// ----------------------------------------------------------------------------------------------------

	miso.IPost("/open/api/user/add",
		func(c *gin.Context, rail miso.Rail, req AddUserParam) (any, error) {
			return nil, AddUser(rail, miso.GetMySQL(), AddUserParam(req), common.GetUser(rail).Username)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Admin add user", Code: resCodeManageUser, Type: goauth.PT_PROTECTED}),
	)

	miso.IPost("/open/api/user/list",
		func(c *gin.Context, rail miso.Rail, req ListUserReq) (miso.PageRes[UserInfo], error) {
			return ListUsers(rail, miso.GetMySQL(), req)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Admin list users", Code: resCodeManageUser, Type: goauth.PT_PROTECTED}),
	)

	miso.IPost("/open/api/user/info/update",
		func(c *gin.Context, rail miso.Rail, req AdminUpdateUserReq) (any, error) {
			return nil, AdminUpdateUser(rail, miso.GetMySQL(), req, common.GetUser(rail))
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Admin update user info", Code: resCodeManageUser, Type: goauth.PT_PROTECTED}),
	)

	miso.IPost("/open/api/user/registration/review",
		func(c *gin.Context, rail miso.Rail, req AdminReviewUserReq) (any, error) {
			return nil, ReviewUserRegistration(rail, miso.GetMySQL(), req)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Admin review user registration", Code: resCodeManageUser, Type: goauth.PT_PROTECTED}),
	)

	miso.Get("/open/api/user/info",
		func(c *gin.Context, rail miso.Rail) (any, error) {
			u := common.GetUser(rail)
			return LoadUserInfoBrief(rail, miso.GetMySQL(), u.Username)
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "User get user info", Code: resCodeBasicUser, Type: goauth.PT_PROTECTED}),
	)

	return nil
}
