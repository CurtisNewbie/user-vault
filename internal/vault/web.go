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

func RegisterRoutes(rail miso.Rail) error {

	RegisterInternalPathResourcesOnBootstrapped()

	miso.BaseRoute("/open/api").Group(
		miso.IPost("/user/login",
			func(gin *gin.Context, rail miso.Rail, req LoginReq) (any, error) {
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
			}).
			Desc("User Login using password, a JWT token is generated and returned").
			Public().
			DocJsonReq(LoginReq{}).
			DocJsonResp(miso.GnResp[string]{}),

		miso.IPost("/user/register/request",
			func(c *gin.Context, rail miso.Rail, req RegisterReq) (any, error) {
				return nil, UserRegister(rail, miso.GetMySQL(), req)
			}).
			Desc("User request registration, approval needed").
			Public().
			DocJsonReq(RegisterReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/user/add",
			func(c *gin.Context, rail miso.Rail, req AddUserParam) (any, error) {
				return nil, AddUser(rail, miso.GetMySQL(), AddUserParam(req), common.GetUser(rail).Username)
			}).
			Desc("Admin create new user").
			Resource(ResourceManagerUser).
			DocJsonReq(AddUserParam{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/user/list",
			func(c *gin.Context, rail miso.Rail, req ListUserReq) (any, error) {
				return ListUsers(rail, miso.GetMySQL(), req)
			}).
			Desc("Admin list users").
			Resource(ResourceManagerUser).
			DocJsonReq(ListUserReq{}).
			DocJsonResp(miso.GnResp[miso.PageRes[api.UserInfo]]{}),

		miso.IPost("/user/info/update",
			func(c *gin.Context, rail miso.Rail, req AdminUpdateUserReq) (any, error) {
				return nil, AdminUpdateUser(rail, miso.GetMySQL(), req, common.GetUser(rail))
			}).
			Desc("Admin update user info").
			Resource(ResourceManagerUser).
			DocJsonReq(AdminUpdateUserReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/user/registration/review",
			func(c *gin.Context, rail miso.Rail, req AdminReviewUserReq) (any, error) {
				return nil, ReviewUserRegistration(rail, miso.GetMySQL(), req)
			}).
			Desc("Admin review user registration").
			Resource(ResourceManagerUser).
			DocJsonReq(AdminReviewUserReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.Get("/user/info",
			func(c *gin.Context, rail miso.Rail) (any, error) {
				timer := miso.NewHistTimer(fetchUserInfoHisto)
				defer timer.ObserveDuration()
				u := common.GetUser(rail)
				return LoadUserBriefThrCache(rail, miso.GetMySQL(), u.Username)
			}).
			Desc("User get user info").
			Resource(ResourceBasicUser).
			DocJsonResp(miso.GnResp[UserDetail]{}),

		miso.IPost("/user/password/update",
			func(c *gin.Context, rail miso.Rail, req UpdatePasswordReq) (any, error) {
				u := common.GetUser(rail)
				return nil, UpdatePassword(rail, miso.GetMySQL(), u.Username, req)
			}).
			Desc("User update password").
			Resource(ResourceBasicUser).
			DocJsonReq(UpdatePasswordReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/token/exchange",
			func(c *gin.Context, rail miso.Rail, req ExchangeTokenReq) (any, error) {
				timer := miso.NewHistTimer(tokenExchangeHisto)
				defer timer.ObserveDuration()
				return ExchangeToken(rail, miso.GetMySQL(), req)
			}).
			Desc("Exchange token").
			Public().
			DocJsonReq(ExchangeTokenReq{}).
			DocJsonResp(miso.GnResp[string]{}),

		miso.Get("/token/user",
			func(c *gin.Context, rail miso.Rail) (any, error) {
				token := c.Query("token")
				return GetTokenUser(rail, miso.GetMySQL(), token)
			}).
			Desc("Get user info by token. This endpoint is expected to be accessible publicly").
			Public().
			DocQueryParam("token", "jwt token").
			DocJsonResp(miso.GnResp[UserInfoBrief]{}),

		miso.IPost("/access/history",
			func(c *gin.Context, rail miso.Rail, req ListAccessLogReq) (any, error) {
				return ListAccessLogs(rail, miso.GetMySQL(), common.GetUser(rail), req)
			}).
			Desc("User list access logs").
			Resource(ResourceBasicUser).
			DocJsonReq(ListAccessLogReq{}).
			DocJsonResp(miso.GnResp[miso.PageRes[ListedAccessLog]]{}),

		miso.IPost("/user/key/generate",
			func(c *gin.Context, rail miso.Rail, req GenUserKeyReq) (any, error) {
				return nil, GenUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).Username)
			}).
			Desc("User generate user key").
			Resource(ResourceBasicUser).
			DocJsonReq(GenUserKeyReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/user/key/list",
			func(c *gin.Context, rail miso.Rail, req ListUserKeysReq) (any, error) {
				return ListUserKeys(rail, miso.GetMySQL(), req, common.GetUser(rail))
			}).
			Desc("User list user keys").
			Resource(ResourceBasicUser).
			DocJsonReq(ListUserKeysReq{}).
			DocJsonResp(miso.GnResp[miso.PageRes[ListedUserKey]]{}),

		miso.IPost("/user/key/delete",
			func(c *gin.Context, rail miso.Rail, req DeleteUserKeyReq) (any, error) {
				return nil, DeleteUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).UserId)
			}).
			Desc("User delete user key").
			Resource(ResourceBasicUser).
			DocJsonReq(DeleteUserKeyReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/resource/add",
			func(c *gin.Context, ec miso.Rail, req CreateResReq) (any, error) {
				user := common.GetUser(ec)
				return nil, CreateResourceIfNotExist(ec, req, user)
			}).
			Desc("Admin add resource").
			Resource(ResourceManageResources).
			DocJsonReq(CreateResReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/resource/remove",
			func(c *gin.Context, ec miso.Rail, req DeleteResourceReq) (any, error) {
				return nil, DeleteResource(ec, req)
			}).
			Desc("Admin remove resource").
			Resource(ResourceManageResources).
			DocJsonReq(DeleteResourceReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.Get("/resource/brief/candidates",
			func(c *gin.Context, ec miso.Rail) (any, error) {
				roleNo := c.Query("roleNo")
				return ListResourceCandidatesForRole(ec, roleNo)
			}).
			Desc("List all resource candidates for role").
			Resource(ResourceManageResources).
			DocQueryParam("roleNo", "Role No").
			DocJsonResp(miso.GnResp[[]ResBrief]{}),

		miso.IPost("/resource/list",
			func(c *gin.Context, ec miso.Rail, req ListResReq) (any, error) {
				return ListResources(ec, req)
			}).
			Desc("Admin list resources").
			Resource(ResourceManageResources).
			DocJsonReq(ListResReq{}).
			DocJsonResp(miso.GnResp[ListResResp]{}),

		miso.Get("/resource/brief/user",
			func(c *gin.Context, ec miso.Rail) (any, error) {
				u := common.GetUser(ec)
				if u.IsNil {
					return []ResBrief{}, nil
				}
				return ListAllResBriefsOfRole(ec, u.RoleNo)
			}).
			Desc("List resources that are accessible to current user").
			Public().
			DocJsonResp(miso.GnResp[[]ResBrief]{}),

		miso.Get("/resource/brief/all",
			func(c *gin.Context, ec miso.Rail) (any, error) {
				return ListAllResBriefs(ec)
			}).
			Desc("List all resource brief info").
			Public().
			DocJsonResp(miso.GnResp[[]ResBrief]{}),

		miso.IPost("/role/resource/add",
			func(c *gin.Context, ec miso.Rail, req AddRoleResReq) (any, error) {
				user := common.GetUser(ec)
				return nil, AddResToRoleIfNotExist(ec, req, user)
			}).
			Desc("Admin add resource to role").
			Resource(ResourceManageResources).
			DocJsonReq(AddRoleResReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/role/resource/remove",
			func(c *gin.Context, ec miso.Rail, req RemoveRoleResReq) (any, error) {
				return nil, RemoveResFromRole(ec, req)
			}).
			Desc("Admin remove resource from role").
			Resource(ResourceManageResources).
			DocJsonReq(RemoveRoleResReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/role/add",
			func(c *gin.Context, ec miso.Rail, req AddRoleReq) (any, error) {
				user := common.GetUser(ec)
				return nil, AddRole(ec, req, user)
			}).
			Desc("Admin add role").
			Resource(ResourceManageResources).
			DocJsonReq(AddRoleReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/role/list",
			func(c *gin.Context, ec miso.Rail, req ListRoleReq) (any, error) {
				return ListRoles(ec, req)
			}).
			Desc("Admin list roles").
			Resource(ResourceManageResources).
			DocJsonReq(ListRoleReq{}).
			DocJsonResp(miso.GnResp[ListRoleResp]{}),

		miso.Get("/role/brief/all",
			func(c *gin.Context, ec miso.Rail) (any, error) {
				return ListAllRoleBriefs(ec)
			}).
			Desc("Admin list role brief info").
			Resource(ResourceManageResources).
			DocJsonResp(miso.GnResp[[]RoleBrief]{}),

		miso.IPost("/role/resource/list",
			func(c *gin.Context, ec miso.Rail, req ListRoleResReq) (any, error) {
				return ListRoleRes(ec, req)
			}).
			Desc("Admin list resources of role").
			Resource(ResourceManageResources).
			DocJsonReq(ListRoleResReq{}).
			DocJsonResp(miso.GnResp[ListRoleResResp]{}),

		miso.IPost("/role/info",
			func(c *gin.Context, ec miso.Rail, req RoleInfoReq) (any, error) {
				return GetRoleInfo(ec, req)
			}).
			Desc("Get role info").
			Public().
			DocJsonReq(RoleInfoReq{}).
			DocJsonResp(miso.GnResp[RoleInfoResp]{}),

		miso.IPost("/path/list",
			func(c *gin.Context, ec miso.Rail, req ListPathReq) (any, error) {
				return ListPaths(ec, req)
			}).
			Desc("Admin list paths").
			Resource(ResourceManageResources).
			DocJsonReq(ListPathReq{}).
			DocJsonResp(miso.GnResp[ListPathResp]{}),

		miso.IPost("/path/resource/bind",
			func(c *gin.Context, ec miso.Rail, req BindPathResReq) (any, error) {
				return nil, BindPathRes(ec, req)
			}).
			Desc("Admin bind resource to path").
			Resource(ResourceManageResources).
			DocJsonReq(BindPathResReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/path/resource/unbind",
			func(c *gin.Context, ec miso.Rail, req UnbindPathResReq) (any, error) {
				return nil, UnbindPathRes(ec, req)
			}).
			Desc("Admin unbind resource and path").
			Resource(ResourceManageResources).
			DocJsonReq(UnbindPathResReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/path/delete",
			func(c *gin.Context, ec miso.Rail, req DeletePathReq) (any, error) {
				return nil, DeletePath(ec, req)
			}).
			Desc("Admin delete path").
			Resource(ResourceManageResources).
			DocJsonReq(DeletePathReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/path/update",
			func(c *gin.Context, ec miso.Rail, req UpdatePathReq) (any, error) {
				return nil, UpdatePath(ec, req)
			}).
			Desc("Admin update path").
			Resource(ResourceManageResources).
			DocJsonReq(UpdatePathReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),
	)

	// ----------------------------------------------------------------------------------------------
	//
	// Internal endpoints
	//
	// ----------------------------------------------------------------------------------------------

	miso.BaseRoute("/remote").Group(

		miso.IPost("/user/info",
			func(c *gin.Context, rail miso.Rail, req api.FindUserReq) (any, error) {
				return ItnFindUserInfo(rail, miso.GetMySQL(), req)
			}).
			Desc("Fetch user info").
			DocJsonReq(api.FindUserReq{}).
			DocJsonResp(miso.GnResp[api.UserInfo]{}),

		miso.Get("/user/id",
			func(c *gin.Context, rail miso.Rail) (any, error) {
				username := c.Query("username")
				u, err := LoadUserBriefThrCache(rail, miso.GetMySQL(), username)
				if err != nil {
					return nil, err
				}
				return u.Id, nil
			}).
			Desc("Fetch id of user with the username").
			DocQueryParam("username", "username of user").
			DocJsonResp(miso.GnResp[int]{}),

		miso.IPost("/user/userno/username",
			func(c *gin.Context, rail miso.Rail, req api.FetchNameByUserNoReq) (any, error) {
				return ItnFindNameOfUserNo(rail, miso.GetMySQL(), req)
			}).
			Desc("Fetch usernames of users with the userNos").
			DocJsonReq(api.FetchNameByUserNoReq{}).
			DocJsonResp(miso.GnResp[api.FetchUsernamesRes]{}),

		miso.IPost("/user/list/with-role",
			func(c *gin.Context, rail miso.Rail, req api.FetchUsersWithRoleReq) (any, error) {
				return ItnFindUsersWithRole(rail, miso.GetMySQL(), req)
			}).
			Desc("Fetch user info of users with the role").
			DocJsonReq(api.FetchUsersWithRoleReq{}).
			DocJsonResp(miso.GnResp[[]api.UserInfo]{}),

		miso.IPost("/resource/add",
			func(c *gin.Context, rail miso.Rail, req CreateResReq) (any, error) {
				user := common.GetUser(rail)
				return nil, CreateResourceIfNotExist(rail, req, user)
			}).
			Desc("Report resource. This endpoint should be used internally by another backend service.").
			DocJsonReq(CreateResReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/path/resource/access-test",
			func(c *gin.Context, rail miso.Rail, req TestResAccessReq) (any, error) {
				timer := miso.NewHistTimer(resourceAccessCheckHisto)
				defer timer.ObserveDuration()
				return TestResourceAccess(rail, req)
			}).
			Desc("Validate resource access").
			DocJsonReq(TestResAccessReq{}).
			DocJsonResp(miso.GnResp[TestResAccessResp]{}),

		miso.IPost("/path/add",
			func(c *gin.Context, rail miso.Rail, req CreatePathReq) (any, error) {
				user := common.GetUser(rail)
				return nil, CreatePathIfNotExist(rail, req, user)
			}).
			Desc("Report endpoint").
			DocJsonReq(CreatePathReq{}).
			DocJsonResp(miso.GnResp[miso.Void]{}),

		miso.IPost("/role/info",
			func(c *gin.Context, rail miso.Rail, req RoleInfoReq) (any, error) {
				return GetRoleInfo(rail, req)
			}).
			Desc("Get role info").
			DocJsonReq(RoleInfoReq{}).
			DocJsonResp(miso.GnResp[RoleInfoResp]{}),
	)
	return nil
}
