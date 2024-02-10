package vault

import (
	"strings"

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

	ResourceManagerUser     = "manage-users"
	ResourceBasicUser       = "basic-user"
	ResourceManageResources = "manage-resources"
)

var (
	fetchUserInfoHisto       = miso.NewPromHisto("user_vault_fetch_user_info_duration")
	tokenExchangeHisto       = miso.NewPromHisto("user_vault_token_exchange_duration")
	resourceAccessCheckHisto = miso.NewPromHisto("user_vault_resource_access_check_duration")
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

func RegisterRoutes(rail miso.Rail) error {

	RegisterInternalPathResourcesOnBootstrapped()

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

	miso.BaseRoute("/open/api/resource").Group(
		miso.IPost("/add", CreateResourceIfNotExistEp).
			Desc("Admin add resource").
			Resource(ResourceManageResources),

		miso.IPost("/remove", DeleteResourceEp).
			Desc("Admin remove resource").
			Resource(ResourceManageResources),

		miso.Get("/brief/candidates", ListResourceCandidatesForRoleEp).
			Desc("List all resource candidates for role").
			Resource(ResourceManageResources),

		miso.IPost("/list", ListResourcesEp).
			Desc("Admin list resources").
			Resource(ResourceManageResources),

		miso.Get("/brief/user", ListAllResBriefsOfRoleEp).
			Desc("List resources of current user").
			Public(),

		miso.Get("/brief/all", ListAllResBriefsEp).
			Desc("List all resource brief info").
			Public(),
	)

	miso.BaseRoute("/open/api/role").Group(
		miso.IPost("/resource/add", AddResToRoleIfNotExistEp).
			Desc("Admin add resource to role").
			Resource(ResourceManageResources),

		miso.IPost("/resource/remove", RemoveResFromRoleEp).
			Desc("Admin remove resource from role").
			Resource(ResourceManageResources),

		miso.IPost("/add", AddRoleEp).
			Desc("Admin add role").
			Resource(ResourceManageResources),

		miso.IPost("/list", ListRolesEp).
			Desc("Admin list roles").
			Resource(ResourceManageResources),

		miso.Get("/brief/all", ListAllRoleBriefsEp).
			Desc("Admin list role brief info").
			Resource(ResourceManageResources),

		miso.IPost("/resource/list", ListRoleResEp).
			Desc("Admin list resources of role").
			Resource(ResourceManageResources),

		miso.IPost("/info", GetRoleInfoEp).
			Desc("Get role info").
			Public(),
	)

	miso.BaseRoute("/open/api/path").Group(
		miso.IPost("/list", ListPathsEp).
			Desc("Admin list paths").
			Resource(ResourceManageResources),

		miso.IPost("/resource/bind", BindPathResEp).
			Desc("Admin bind resource to path").
			Resource(ResourceManageResources),

		miso.IPost("/resource/unbind", UnbindPathResEp).
			Desc("Admin unbind resource and path").
			Resource(ResourceManageResources),

		miso.IPost("/delete", DeletePathEp).
			Desc("Admin delete path").
			Resource(ResourceManageResources),

		miso.IPost("/update", UpdatePathEp).
			Desc("Admin update path").
			Resource(ResourceManageResources),
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

		miso.IPost("/resource/add",
			func(c *gin.Context, rail miso.Rail, req CreateResReq) (any, error) {
				user := common.GetUser(rail)
				return nil, CreateResourceIfNotExist(rail, req, user)
			}),
		miso.IPost("/path/resource/access-test",
			func(c *gin.Context, rail miso.Rail, req TestResAccessReq) (any, error) {
				timer := miso.NewHistTimer(resourceAccessCheckHisto)
				defer timer.ObserveDuration()

				return TestResourceAccess(rail, req)
			}),
		miso.IPost("/path/add",
			func(c *gin.Context, rail miso.Rail, req CreatePathReq) (any, error) {
				user := common.GetUser(rail)
				return nil, CreatePathIfNotExist(rail, req, user)
			}),
		miso.IPost("/role/info",
			func(c *gin.Context, rail miso.Rail, req RoleInfoReq) (any, error) {
				return GetRoleInfo(rail, req)
			}),
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

type PathDoc struct {
	Desc   string
	Type   PathType
	Method string
	Code   string
}

func ListAllResBriefsOfRoleEp(c *gin.Context, ec miso.Rail) (any, error) {
	u := common.GetUser(ec)
	if u.IsNil {
		return []ResBrief{}, nil
	}
	return ListAllResBriefsOfRole(ec, u.RoleNo)
}

func ListAllResBriefsEp(c *gin.Context, ec miso.Rail) (any, error) {
	return ListAllResBriefs(ec)
}

func GetRoleInfoEp(c *gin.Context, ec miso.Rail, req RoleInfoReq) (any, error) {
	return GetRoleInfo(ec, req)
}

func CreateResourceIfNotExistEp(c *gin.Context, ec miso.Rail, req CreateResReq) (any, error) {
	user := common.GetUser(ec)
	return nil, CreateResourceIfNotExist(ec, req, user)
}

func DeleteResourceEp(c *gin.Context, ec miso.Rail, req DeleteResourceReq) (any, error) {
	return nil, DeleteResource(ec, req)
}

func ListResourceCandidatesForRoleEp(c *gin.Context, ec miso.Rail) (any, error) {
	roleNo := c.Query("roleNo")
	return ListResourceCandidatesForRole(ec, roleNo)
}

func ListResourcesEp(c *gin.Context, ec miso.Rail, req ListResReq) (any, error) {
	return ListResources(ec, req)
}

func AddResToRoleIfNotExistEp(c *gin.Context, ec miso.Rail, req AddRoleResReq) (any, error) {
	user := common.GetUser(ec)
	return nil, AddResToRoleIfNotExist(ec, req, user)
}

func RemoveResFromRoleEp(c *gin.Context, ec miso.Rail, req RemoveRoleResReq) (any, error) {
	return nil, RemoveResFromRole(ec, req)
}

func AddRoleEp(c *gin.Context, ec miso.Rail, req AddRoleReq) (any, error) {
	user := common.GetUser(ec)
	return nil, AddRole(ec, req, user)
}

func ListRolesEp(c *gin.Context, ec miso.Rail, req ListRoleReq) (any, error) {
	return ListRoles(ec, req)
}

func ListAllRoleBriefsEp(c *gin.Context, ec miso.Rail) (any, error) {
	return ListAllRoleBriefs(ec)
}

func ListRoleResEp(c *gin.Context, ec miso.Rail, req ListRoleResReq) (any, error) {
	return ListRoleRes(ec, req)
}

func ListPathsEp(c *gin.Context, ec miso.Rail, req ListPathReq) (any, error) {
	return ListPaths(ec, req)
}

func BindPathResEp(c *gin.Context, ec miso.Rail, req BindPathResReq) (any, error) {
	return nil, BindPathRes(ec, req)
}

func UnbindPathResEp(c *gin.Context, ec miso.Rail, req UnbindPathResReq) (any, error) {
	return nil, UnbindPathRes(ec, req)
}

func DeletePathEp(c *gin.Context, ec miso.Rail, req DeletePathReq) (any, error) {
	return nil, DeletePath(ec, req)
}

func UpdatePathEp(c *gin.Context, ec miso.Rail, req UpdatePathReq) (any, error) {
	return nil, UpdatePath(ec, req)
}

func RegisterInternalPathResourcesOnBootstrapped() {

	miso.PostServerBootstrapped(func(rail miso.Rail) error {

		res := []goauth.AddResourceReq{
			{Code: ResourceManageResources, Name: "Manage Resources Access"},
			{Code: ResourceManagerUser, Name: "Admin Manage Users"},
			{Code: ResourceBasicUser, Name: "Basic User Operation"},
		}
		user := common.NilUser()

		app := miso.GetPropStr(miso.PropAppName)
		for _, res := range res {
			if res.Code == "" || res.Name == "" {
				continue
			}
			if e := CreateResourceIfNotExist(rail, CreateResReq(res), user); e != nil {
				return e
			}
		}

		routes := miso.GetHttpRoutes()
		for _, route := range routes {
			if route.Url == "" {
				continue
			}
			var routeType = PtProtected
			if route.Scope == miso.ScopePublic {
				routeType = PtPublic
			}

			url := route.Url
			if !strings.HasPrefix(url, "/") {
				url = "/" + url
			}

			r := CreatePathReq{
				Method:  route.Method,
				Group:   app,
				Url:     "/" + app + url,
				Type:    routeType,
				Desc:    route.Desc,
				ResCode: route.Resource,
			}
			if err := CreatePathIfNotExist(rail, r, user); err != nil {
				return err
			}
		}
		return nil
	})
}
