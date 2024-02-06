package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/goauth"
	"github.com/curtisnewbie/miso/miso"
	"github.com/curtisnewbie/user-vault/api"
	"github.com/gin-gonic/gin"
)

const (
	headerForwardedFor = "X-Forwarded-For"
	headerUserAgent    = "User-Agent"

	passwordLoginUrl = "/user-vault/open/api/user/login"

	ResourceManagerUser = "manage-users"
	ResourceBasicUser   = "basic-user"
)

var (
	fetchUserInfoHisto = miso.NewPromHisto("user_vault_fetch_user_info_duration")
	tokenExchangeHisto = miso.NewPromHisto("user_vault_token_exchange_duration")
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
	Username   *string     `json:"username"`
	RoleNo     *string     `json:"roleNo"`
	IsDisabled *int        `json:"isDisabled"`
	Paging     miso.Paging `json:"pagingVo"`
}

type AdminUpdateUserReq struct {
	Id         int    `json:"id" valid:"positive"`
	RoleNo     string `json:"roleNo" valid:"notEmpty"`
	IsDisabled int    `json:"isDisabled"`
}

type AdminReviewUserReq struct {
	UserId       int    `json:"userId" valid:"positive"`
	ReviewStatus string `json:"reviewStatus"`
}

type RegisterReq struct {
	Username string `json:"username" valid:"notEmpty"`
	Password string `json:"password" valid:"notEmpty"`
}

func registerRoutes(rail miso.Rail) error {

	goauth.ReportOnBoostrapped(rail, []goauth.AddResourceReq{
		{Code: ResourceManagerUser, Name: "Admin Manage Users"},
		{Code: ResourceBasicUser, Name: "Basic User Operation"},
	})

	miso.BaseRoute("/open/api").Group(
		miso.IPost("/user/login", UserLoginEp).
			Desc("User Login (password-based)").
			Public(),

		miso.IPost("/user/register/request", UserReqRegisterEp).
			Desc("User request registration").
			Public(),

		miso.IPost("/user/add", AddUserEp).
			Desc("Admin add user").
			Resource(ResourceManagerUser),

		miso.IPost("/user/list", ListUserEp).
			Desc("Admin list users").
			Resource(ResourceManagerUser),

		miso.IPost("/user/info/update", UpdateUserEp).
			Desc("Admin update user info").
			Resource(ResourceManagerUser),

		miso.IPost("/user/registration/review", ReviewUserRegistrationEp).
			Desc("Admin review user registration").
			Resource(ResourceManagerUser),

		miso.Get("/user/info", GetUserInfEp).
			Desc("User get user info").
			Resource(ResourceBasicUser),

		// deprecated, we can just use /user/info instead
		miso.Get("/user/detail", GetUserDetailEp).
			Desc("User get user details").
			Resource(ResourceBasicUser),

		miso.IPost("/user/password/update", UpdateUserEp).
			Desc("User update password").
			Resource(ResourceBasicUser),

		miso.IPost("/token/exchange", ExchangeTokenEp).
			Desc("Exchange token").
			Public(),

		miso.Get("/token/user", GetUserTokenEp).
			Desc("Get user info by token").
			Public(),

		miso.IPost("/access/history", ListAccessLogEp).
			Desc("List access logs").
			Resource(ResourceBasicUser),

		miso.IPost("/user/key/generate", GenUserKeyEp).
			Desc("User generate user key").
			Resource(ResourceBasicUser),

		miso.IPost("/user/key/list", ListUserKeyEp).
			Desc("User list user keys").
			Resource(ResourceBasicUser),

		miso.IPost("/user/key/delete", DeleteUserKeyEp).
			Desc("User delete user key").
			Resource(ResourceBasicUser),
	)

	// ----------------------------------------------------------------------------------------------
	//
	// Internal endpoints
	//
	// ----------------------------------------------------------------------------------------------

	miso.BaseRoute("/remote").Group(
		miso.Get("/user/username", ItnFetchNameByIdEp),
		miso.IPost("/user/info", ItnFetchUserInfoEp),
		miso.Get("/user/id", ItnFetchUserIdEp),
		miso.IPost("/user/userno/username", ItnFetchNameByUserNoEp),
		miso.IPost("/user/list/with-role", ItnFetchUsersWithRoleEp),
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
	timer := miso.NewHistTimer(fetchUserInfoHisto)
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
	timer := miso.NewHistTimer(tokenExchangeHisto)
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

func ItnFetchNameByUserNoEp(c *gin.Context, rail miso.Rail, req api.FetchNameByUserNoReq) (any, error) {
	return ItnFindNameOfUserNo(rail, miso.GetMySQL(), req)
}

func ItnFetchUsersWithRoleEp(c *gin.Context, rail miso.Rail, req api.FetchUsersWithRoleReq) (any, error) {
	return ItnFindUsersWithRole(rail, miso.GetMySQL(), req)
}

func ItnFetchUserIdEp(c *gin.Context, rail miso.Rail) (any, error) {
	username := c.Query("username")
	u, err := LoadUserBriefThrCache(rail, miso.GetMySQL(), username)
	if err != nil {
		return nil, err
	}
	return u.Id, nil
}

func ItnFetchUserInfoEp(c *gin.Context, rail miso.Rail, req api.FindUserReq) (any, error) {
	return ItnFindUserInfo(rail, miso.GetMySQL(), req)
}

func ItnFetchNameByIdEp(c *gin.Context, rail miso.Rail) (any, error) {
	return FindUsername(rail, miso.GetMySQL(), c.Query("id"))
}
