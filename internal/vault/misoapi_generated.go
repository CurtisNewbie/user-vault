// auto generated by misoapi v0.1.8 at 2024/09/17 21:43:23, please do not modify
package vault

import (
	"github.com/curtisnewbie/miso/miso"
	"github.com/curtisnewbie/user-vault/api"
)

func init() {
	miso.IPost("/open/api/user/login",
		func(inb *miso.Inbound, req LoginReq) (string, error) {
			return UserLoginEp(inb, req)
		}).
		Desc("User Login using password, a JWT token is generated and returned").
		Public()

	miso.IPost("/open/api/user/register/request",
		func(inb *miso.Inbound, req RegisterReq) (any, error) {
			return UserRegisterEp(inb, req)
		}).
		Desc("User request registration, approval needed").
		Public()

	miso.IPost("/open/api/user/add",
		func(inb *miso.Inbound, req AddUserParam) (any, error) {
			return AdminAddUserEp(inb, req)
		}).
		Desc("Admin create new user").
		Resource(ResourceManagerUser)

	miso.IPost("/open/api/user/list",
		func(inb *miso.Inbound, req ListUserReq) (miso.PageRes[api.UserInfo], error) {
			return AdminListUsersEp(inb, req)
		}).
		Desc("Admin list users").
		Resource(ResourceManagerUser)

	miso.IPost("/open/api/user/info/update",
		func(inb *miso.Inbound, req AdminUpdateUserReq) (any, error) {
			return AdminUpdateUserEp(inb, req)
		}).
		Desc("Admin update user info").
		Resource(ResourceManagerUser)

	miso.IPost("/open/api/user/registration/review",
		func(inb *miso.Inbound, req AdminReviewUserReq) (any, error) {
			return AdminReviewUserEp(inb, req)
		}).
		Desc("Admin review user registration").
		Resource(ResourceManagerUser)

	miso.Get("/open/api/user/info",
		func(inb *miso.Inbound) (UserInfoRes, error) {
			return UserGetUserInfoEp(inb)
		}).
		Desc("User get user info").
		Public()

	miso.IPost("/open/api/user/password/update",
		func(inb *miso.Inbound, req UpdatePasswordReq) (any, error) {
			return UserUpdatePasswordEp(inb, req)
		}).
		Desc("User update password").
		Resource(ResourceBasicUser)

	miso.IPost("/open/api/token/exchange",
		func(inb *miso.Inbound, req ExchangeTokenReq) (string, error) {
			return ExchangeTokenEp(inb, req)
		}).
		Desc("Exchange token").
		Public()

	miso.IGet("/open/api/token/user",
		func(inb *miso.Inbound, req GetTokenUserReq) (UserInfoBrief, error) {
			return GetTokenUserInfoEp(inb, req)
		}).
		Desc("Get user info by token. This endpoint is expected to be accessible publicly").
		Public()

	miso.IPost("/open/api/access/history",
		func(inb *miso.Inbound, req ListAccessLogReq) (miso.PageRes[ListedAccessLog], error) {
			return UserListAccessHistoryEp(inb, req)
		}).
		Desc("User list access logs").
		Resource(ResourceBasicUser)

	miso.IPost("/open/api/user/key/generate",
		func(inb *miso.Inbound, req GenUserKeyReq) (any, error) {
			return UserGenUserKeyEp(inb, req)
		}).
		Desc("User generate user key").
		Resource(ResourceBasicUser)

	miso.IPost("/open/api/user/key/list",
		func(inb *miso.Inbound, req ListUserKeysReq) (miso.PageRes[ListedUserKey], error) {
			return UserListUserKeysEp(inb, req)
		}).
		Desc("User list user keys").
		Resource(ResourceBasicUser)

	miso.IPost("/open/api/user/key/delete",
		func(inb *miso.Inbound, req DeleteUserKeyReq) (any, error) {
			return UserDeleteUserKeyEp(inb, req)
		}).
		Desc("User delete user key").
		Resource(ResourceBasicUser)

	miso.IPost("/open/api/resource/add",
		func(inb *miso.Inbound, req CreateResReq) (any, error) {
			return AdminAddResourceEp(inb, req)
		}).
		Desc("Admin add resource").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/resource/remove",
		func(inb *miso.Inbound, req DeleteResourceReq) (any, error) {
			return AdminRemoveResourceEp(inb, req)
		}).
		Desc("Admin remove resource").
		Resource(ResourceManageResources)

	miso.IGet("/open/api/resource/brief/candidates",
		func(inb *miso.Inbound, req ListResCandidatesReq) ([]ResBrief, error) {
			return ListResCandidatesEp(inb, req)
		}).
		Desc("List all resource candidates for role").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/resource/list",
		func(inb *miso.Inbound, req ListResReq) (ListResResp, error) {
			return AdminListResEp(inb, req)
		}).
		Desc("Admin list resources").
		Resource(ResourceManageResources)

	miso.Get("/open/api/resource/brief/user",
		func(inb *miso.Inbound) ([]ResBrief, error) {
			return ListUserAccessibleResEp(inb)
		}).
		Desc("List resources that are accessible to current user").
		Public()

	miso.Get("/open/api/resource/brief/all",
		func(inb *miso.Inbound) ([]ResBrief, error) {
			return ListAllResBriefEp(inb)
		}).
		Desc("List all resource brief info").
		Public()

	miso.IPost("/open/api/role/resource/add",
		func(inb *miso.Inbound, req AddRoleResReq) (any, error) {
			return AdminBindRoleResEp(inb, req)
		}).
		Desc("Admin add resource to role").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/role/resource/remove",
		func(inb *miso.Inbound, req RemoveRoleResReq) (any, error) {
			return AdminUnbindRoleResEp(inb, req)
		}).
		Desc("Admin remove resource from role").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/role/add",
		func(inb *miso.Inbound, req AddRoleReq) (any, error) {
			return AdminAddRoleEp(inb, req)
		}).
		Desc("Admin add role").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/role/list",
		func(inb *miso.Inbound, req ListRoleReq) (ListRoleResp, error) {
			return AdminListRolesEp(inb, req)
		}).
		Desc("Admin list roles").
		Resource(ResourceManageResources)

	miso.Get("/open/api/role/brief/all",
		func(inb *miso.Inbound) ([]RoleBrief, error) {
			return AdminListRoleBriefsEp(inb)
		}).
		Desc("Admin list role brief info").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/role/resource/list",
		func(inb *miso.Inbound, req ListRoleResReq) (ListRoleResResp, error) {
			return AdminListRoleResEp(inb, req)
		}).
		Desc("Admin list resources of role").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/role/info",
		func(inb *miso.Inbound, req api.RoleInfoReq) (api.RoleInfoResp, error) {
			return GetRoleInfoEp(inb, req)
		}).
		Desc("Get role info").
		Public()

	miso.IPost("/open/api/path/list",
		func(inb *miso.Inbound, req ListPathReq) (ListPathResp, error) {
			return AdminListPathsEp(inb, req)
		}).
		Desc("Admin list paths").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/path/resource/bind",
		func(inb *miso.Inbound, req BindPathResReq) (any, error) {
			return AdminBindResPathEp(inb, req)
		}).
		Desc("Admin bind resource to path").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/path/resource/unbind",
		func(inb *miso.Inbound, req UnbindPathResReq) (any, error) {
			return AdminUnbindResPathEp(inb, req)
		}).
		Desc("Admin unbind resource and path").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/path/delete",
		func(inb *miso.Inbound, req DeletePathReq) (any, error) {
			return AdminDeletePathEp(inb, req)
		}).
		Desc("Admin delete path").
		Resource(ResourceManageResources)

	miso.IPost("/open/api/path/update",
		func(inb *miso.Inbound, req UpdatePathReq) (any, error) {
			return AdminUpdatePathEp(inb, req)
		}).
		Desc("Admin update path").
		Resource(ResourceManageResources)

	miso.IPost("/remote/user/info",
		func(inb *miso.Inbound, req api.FindUserReq) (api.UserInfo, error) {
			return ItnFetchUserInfoEp(inb, req)
		}).
		Desc("Fetch user info")

	miso.IGet("/remote/user/id",
		func(inb *miso.Inbound, req FetchUserIdByNameReq) (int, error) {
			return ItnFetchUserIdByNameEp(inb, req)
		}).
		Desc("Fetch id of user with the username")

	miso.IPost("/remote/user/userno/username",
		func(inb *miso.Inbound, req api.FetchNameByUserNoReq) (api.FetchUsernamesRes, error) {
			return ItnFetchUsernamesByNosEp(inb, req)
		}).
		Desc("Fetch usernames of users with the userNos")

	miso.IPost("/remote/user/list/with-role",
		func(inb *miso.Inbound, req api.FetchUsersWithRoleReq) ([]api.UserInfo, error) {
			return ItnFindUserWithRoleEp(inb, req)
		}).
		Desc("Fetch users with the role_no")

	miso.IPost("/remote/user/list/with-resource",
		func(inb *miso.Inbound, req api.FetchUserWithResourceReq) ([]api.UserInfo, error) {
			return ItnFindUserWithResourceEp(inb, req)
		}).
		Desc("Fetch users that have access to the resource")

	miso.IPost("/remote/resource/add",
		func(inb *miso.Inbound, req CreateResReq) (any, error) {
			return ItnReportResourceEp(inb, req)
		}).
		Desc("Report resource. This endpoint should be used internally by another backend service.")

	miso.IPost("/remote/path/resource/access-test",
		func(inb *miso.Inbound, req TestResAccessReq) (TestResAccessResp, error) {
			return ItnCheckResourceAccessEp(inb, req)
		}).
		Desc("Validate resource access")

	miso.IPost("/remote/path/add",
		func(inb *miso.Inbound, req CreatePathReq) (any, error) {
			return ItnReportPathEp(inb, req)
		}).
		Desc("Report endpoint info")

}
