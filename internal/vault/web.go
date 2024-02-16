package vault

import (
	"strings"

	"github.com/curtisnewbie/gocommon/auth"
	"github.com/curtisnewbie/gocommon/common"
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

type UserInfoRes struct {
	Id           int
	Username     string
	RoleName     string
	RoleNo       string
	UserNo       string
	RegisterDate string
}

type GetTokenUserReq struct {
	Token string `form:"token" desc:"jwt token"`
}

type ListResCandidatesReq struct {
	RoleNo string `form:"roleNo" desc:"Role No"`
}

type FetchUserIdByNameReq struct {
	Username string `form:"username" desc:"Username"`
}

func RegisterInternalPathResourcesOnBootstrapped() {

	miso.PostServerBootstrapped(func(rail miso.Rail) error {

		res := []auth.Resource{
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

	miso.GroupRoute("/open/api",

		miso.IPost("/user/login", UserLoginEp).
			Desc("User Login using password, a JWT token is generated and returned").
			Public(),

		miso.IPost("/user/register/request", UserRegisterEp).
			Desc("User request registration, approval needed").
			Public(),

		miso.IPost("/user/add", AdminAddUserEp).
			Desc("Admin create new user").
			Resource(ResourceManagerUser),

		miso.IPost("/user/list", AdminListUsersEp).
			Desc("Admin list users").
			Resource(ResourceManagerUser),

		miso.IPost("/user/info/update", AdminUpdateUserEp).
			Desc("Admin update user info").
			Resource(ResourceManagerUser),

		miso.IPost("/user/registration/review", AdminReviewUserEp).
			Desc("Admin review user registration").
			Resource(ResourceManagerUser),

		miso.Get("/user/info", UserGetUserInfoEp).
			Desc("User get user info").
			Resource(ResourceBasicUser),

		miso.IPost("/user/password/update", UserUpdatePasswordEp).
			Desc("User update password").
			Resource(ResourceBasicUser),

		miso.IPost("/token/exchange", ExchangeTokenEp).
			Desc("Exchange token").
			Public(),

		miso.IGet("/token/user", GetTokenUserInfoEp).
			Desc("Get user info by token. This endpoint is expected to be accessible publicly").
			Public(),

		miso.IPost("/access/history", UserListAccessHistoryEp).
			Desc("User list access logs").
			Resource(ResourceBasicUser),

		miso.IPost("/user/key/generate", UserGenUserKeyEp).
			Desc("User generate user key").
			Resource(ResourceBasicUser),

		miso.IPost("/user/key/list", UserListUserKeysEp).
			Desc("User list user keys").
			Resource(ResourceBasicUser),

		miso.IPost("/user/key/delete", UserDeleteUserKeyEp).
			Desc("User delete user key").
			Resource(ResourceBasicUser),

		miso.IPost("/resource/add", AdminAddResourceEp).
			Desc("Admin add resource").
			Resource(ResourceManageResources),

		miso.IPost("/resource/remove", AdminRemoveResourceEp).
			Desc("Admin remove resource").
			Resource(ResourceManageResources),

		miso.IGet("/resource/brief/candidates", ListResCandidatesEp).
			Desc("List all resource candidates for role").
			Resource(ResourceManageResources),

		miso.IPost("/resource/list", AdminListResEp).
			Desc("Admin list resources").
			Resource(ResourceManageResources),

		miso.Get("/resource/brief/user", ListUserAccessibleResEp).
			Desc("List resources that are accessible to current user").
			Public(),

		miso.Get("/resource/brief/all", ListAllResBriefEp).
			Desc("List all resource brief info").
			Public(),

		miso.IPost("/role/resource/add", AdminBindRoleResEp).
			Desc("Admin add resource to role").
			Resource(ResourceManageResources),

		miso.IPost("/role/resource/remove", AdminUnbindRoleResEp).
			Desc("Admin remove resource from role").
			Resource(ResourceManageResources),

		miso.IPost("/role/add", AdminAddRoleEp).
			Desc("Admin add role").
			Resource(ResourceManageResources),

		miso.IPost("/role/list", AdminListRolesEp).
			Desc("Admin list roles").
			Resource(ResourceManageResources),

		miso.Get("/role/brief/all", AdminListRoleBriefsEp).
			Desc("Admin list role brief info").
			Resource(ResourceManageResources),

		miso.IPost("/role/resource/list", AdminListRoleResEp).
			Desc("Admin list resources of role").
			Resource(ResourceManageResources),

		miso.IPost("/role/info", GetRoleInfoEp).
			Desc("Get role info").
			Public(),

		miso.IPost("/path/list", AdminListPathsEp).
			Desc("Admin list paths").
			Resource(ResourceManageResources),

		miso.IPost("/path/resource/bind", AdminBindResPathEp).
			Desc("Admin bind resource to path").
			Resource(ResourceManageResources),

		miso.IPost("/path/resource/unbind", AdminUnbindResPathEp).
			Desc("Admin unbind resource and path").
			Resource(ResourceManageResources),

		miso.IPost("/path/delete", AdminDeletePathEp).
			Desc("Admin delete path").
			Resource(ResourceManageResources),

		miso.IPost("/path/update", AdminUpdatePathEp).
			Desc("Admin update path").
			Resource(ResourceManageResources),
	)

	// ----------------------------------------------------------------------------------------------
	//
	// Internal endpoints
	//
	// ----------------------------------------------------------------------------------------------

	miso.BaseRoute("/remote").Group(

		miso.IPost("/user/info", ItnFetchUserInfoEp).
			Desc("Fetch user info"),

		miso.IGet("/user/id", ItnFetchUserIdByNameEp).
			Desc("Fetch id of user with the username"),

		miso.IPost("/user/userno/username", ItnFetchUsernamesByNosEp).
			Desc("Fetch usernames of users with the userNos"),

		miso.IPost("/user/list/with-role", ItnFindUserWithRoleEp).
			Desc("Fetch user info of users with the role"),

		miso.IPost("/resource/add", ItnReportResourceEp).
			Desc("Report resource. This endpoint should be used internally by another backend service."),

		miso.IPost("/path/resource/access-test", ItnCheckResourceAccessEp).
			Desc("Validate resource access"),

		miso.IPost("/path/add", ItnReportPathEp).
			Desc("Report endpoint info"),
	)
	return nil
}

func UserLoginEp(gin *gin.Context, rail miso.Rail, req LoginReq) (miso.GnResp[string], error) {
	token, user, err := UserLogin(rail, miso.GetMySQL(), PasswordLoginParam(req))
	if err != nil {
		return miso.WrapGnResp("", err)
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
	return miso.WrapGnResp(token, err)
}

func UserRegisterEp(c *gin.Context, rail miso.Rail, req RegisterReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), UserRegister(rail, miso.GetMySQL(), req)
}

func AdminAddUserEp(c *gin.Context, rail miso.Rail, req AddUserParam) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), AddUser(rail, miso.GetMySQL(), AddUserParam(req), common.GetUser(rail).Username)
}

func AdminListUsersEp(c *gin.Context, rail miso.Rail, req ListUserReq) (miso.GnResp[miso.PageRes[api.UserInfo]], error) {
	return miso.WrapGnResp(ListUsers(rail, miso.GetMySQL(), req))
}

func AdminUpdateUserEp(c *gin.Context, rail miso.Rail, req AdminUpdateUserReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), AdminUpdateUser(rail, miso.GetMySQL(), req, common.GetUser(rail))
}

func AdminReviewUserEp(c *gin.Context, rail miso.Rail, req AdminReviewUserReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), ReviewUserRegistration(rail, miso.GetMySQL(), req)
}

func UserGetUserInfoEp(c *gin.Context, rail miso.Rail) (miso.GnResp[UserInfoRes], error) {
	timer := miso.NewHistTimer(fetchUserInfoHisto)
	defer timer.ObserveDuration()
	u := common.GetUser(rail)
	res, err := LoadUserBriefThrCache(rail, miso.GetMySQL(), u.Username)

	if err != nil {
		return miso.GnResp[UserInfoRes]{}, err
	}

	return miso.OkGnResp(UserInfoRes{
		Id:           res.Id,
		Username:     res.Username,
		RoleName:     res.RoleName,
		RoleNo:       res.RoleNo,
		UserNo:       res.UserNo,
		RegisterDate: res.RegisterDate,
	}), nil
}

func UserUpdatePasswordEp(c *gin.Context, rail miso.Rail, req UpdatePasswordReq) (miso.GnResp[miso.Void], error) {
	u := common.GetUser(rail)
	return miso.VoidResp(), UpdatePassword(rail, miso.GetMySQL(), u.Username, req)
}

func ExchangeTokenEp(c *gin.Context, rail miso.Rail, req ExchangeTokenReq) (miso.GnResp[string], error) {
	timer := miso.NewHistTimer(tokenExchangeHisto)
	defer timer.ObserveDuration()
	return miso.WrapGnResp(ExchangeToken(rail, miso.GetMySQL(), req))
}

func GetTokenUserInfoEp(c *gin.Context, rail miso.Rail, req GetTokenUserReq) (miso.GnResp[UserInfoBrief], error) {
	return miso.WrapGnResp(GetTokenUser(rail, miso.GetMySQL(), req.Token))
}

func UserListAccessHistoryEp(c *gin.Context, rail miso.Rail, req ListAccessLogReq) (miso.GnResp[miso.PageRes[ListedAccessLog]], error) {
	return miso.WrapGnResp(ListAccessLogs(rail, miso.GetMySQL(), common.GetUser(rail), req))
}

func UserGenUserKeyEp(c *gin.Context, rail miso.Rail, req GenUserKeyReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), GenUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).Username)
}

func UserListUserKeysEp(c *gin.Context, rail miso.Rail, req ListUserKeysReq) (miso.GnResp[miso.PageRes[ListedUserKey]], error) {
	return miso.WrapGnResp(ListUserKeys(rail, miso.GetMySQL(), req, common.GetUser(rail)))
}

func UserDeleteUserKeyEp(c *gin.Context, rail miso.Rail, req DeleteUserKeyReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), DeleteUserKey(rail, miso.GetMySQL(), req, common.GetUser(rail).UserId)
}

func AdminAddResourceEp(c *gin.Context, rail miso.Rail, req CreateResReq) (miso.GnResp[miso.Void], error) {
	user := common.GetUser(rail)
	return miso.VoidResp(), CreateResourceIfNotExist(rail, req, user)
}

func AdminRemoveResourceEp(c *gin.Context, rail miso.Rail, req DeleteResourceReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), DeleteResource(rail, req)
}

func ListResCandidatesEp(c *gin.Context, rail miso.Rail, req ListResCandidatesReq) (miso.GnResp[[]ResBrief], error) {
	return miso.WrapGnResp(ListResourceCandidatesForRole(rail, req.RoleNo))
}

func AdminListResEp(c *gin.Context, rail miso.Rail, req ListResReq) (miso.GnResp[ListResResp], error) {
	return miso.WrapGnResp(ListResources(rail, req))
}

func ListUserAccessibleResEp(c *gin.Context, rail miso.Rail) (miso.GnResp[[]ResBrief], error) {
	u := common.GetUser(rail)
	if u.IsNil {
		return miso.OkGnResp([]ResBrief{}), nil
	}
	return miso.WrapGnResp(ListAllResBriefsOfRole(rail, u.RoleNo))
}

func ListAllResBriefEp(c *gin.Context, rail miso.Rail) (miso.GnResp[[]ResBrief], error) {
	return miso.WrapGnResp(ListAllResBriefs(rail))
}

func AdminBindRoleResEp(c *gin.Context, rail miso.Rail, req AddRoleResReq) (miso.GnResp[miso.Void], error) {
	user := common.GetUser(rail)
	return miso.VoidResp(), AddResToRoleIfNotExist(rail, req, user)
}

func AdminUnbindRoleResEp(c *gin.Context, rail miso.Rail, req RemoveRoleResReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), RemoveResFromRole(rail, req)
}

func AdminAddRoleEp(c *gin.Context, rail miso.Rail, req AddRoleReq) (miso.GnResp[miso.Void], error) {
	user := common.GetUser(rail)
	return miso.VoidResp(), AddRole(rail, req, user)
}

func AdminListRolesEp(c *gin.Context, rail miso.Rail, req ListRoleReq) (miso.GnResp[ListRoleResp], error) {
	return miso.WrapGnResp(ListRoles(rail, req))
}

func AdminListRoleBriefsEp(c *gin.Context, rail miso.Rail) (miso.GnResp[[]RoleBrief], error) {
	return miso.WrapGnResp(ListAllRoleBriefs(rail))
}

func AdminListRoleResEp(c *gin.Context, rail miso.Rail, req ListRoleResReq) (miso.GnResp[ListRoleResResp], error) {
	return miso.WrapGnResp(ListRoleRes(rail, req))
}

func GetRoleInfoEp(c *gin.Context, rail miso.Rail, req api.RoleInfoReq) (miso.GnResp[api.RoleInfoResp], error) {
	return miso.WrapGnResp(GetRoleInfo(rail, req))
}

func AdminListPathsEp(c *gin.Context, rail miso.Rail, req ListPathReq) (miso.GnResp[ListPathResp], error) {
	return miso.WrapGnResp(ListPaths(rail, req))
}

func AdminBindResPathEp(c *gin.Context, rail miso.Rail, req BindPathResReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), BindPathRes(rail, req)
}

func AdminUnbindResPathEp(c *gin.Context, rail miso.Rail, req UnbindPathResReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), UnbindPathRes(rail, req)
}

func AdminDeletePathEp(c *gin.Context, rail miso.Rail, req DeletePathReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), DeletePath(rail, req)
}

func AdminUpdatePathEp(c *gin.Context, rail miso.Rail, req UpdatePathReq) (miso.GnResp[miso.Void], error) {
	return miso.VoidResp(), UpdatePath(rail, req)
}

func ItnFetchUserInfoEp(c *gin.Context, rail miso.Rail, req api.FindUserReq) (miso.GnResp[api.UserInfo], error) {
	return miso.WrapGnResp(ItnFindUserInfo(rail, miso.GetMySQL(), req))
}

func ItnFetchUserIdByNameEp(c *gin.Context, rail miso.Rail, req FetchUserIdByNameReq) (miso.GnResp[int], error) {
	u, err := LoadUserBriefThrCache(rail, miso.GetMySQL(), req.Username)
	return miso.WrapGnResp(u.Id, err)
}

func ItnFetchUsernamesByNosEp(c *gin.Context, rail miso.Rail, req api.FetchNameByUserNoReq) (miso.GnResp[api.FetchUsernamesRes], error) {
	return miso.WrapGnResp(ItnFindNameOfUserNo(rail, miso.GetMySQL(), req))
}

func ItnFindUserWithRoleEp(c *gin.Context, rail miso.Rail, req api.FetchUsersWithRoleReq) (miso.GnResp[[]api.UserInfo], error) {
	return miso.WrapGnResp(ItnFindUsersWithRole(rail, miso.GetMySQL(), req))
}

func ItnReportResourceEp(c *gin.Context, rail miso.Rail, req CreateResReq) (miso.GnResp[miso.Void], error) {
	user := common.GetUser(rail)
	return miso.VoidResp(), CreateResourceIfNotExist(rail, req, user)
}

func ItnCheckResourceAccessEp(c *gin.Context, rail miso.Rail, req TestResAccessReq) (miso.GnResp[TestResAccessResp], error) {
	timer := miso.NewHistTimer(resourceAccessCheckHisto)
	defer timer.ObserveDuration()
	return miso.WrapGnResp(TestResourceAccess(rail, req))
}

func ItnReportPathEp(c *gin.Context, rail miso.Rail, req CreatePathReq) (miso.GnResp[miso.Void], error) {
	user := common.GetUser(rail)
	return miso.VoidResp(), CreatePathIfNotExist(rail, req, user)
}
