package api

import (
	"fmt"

	"github.com/curtisnewbie/miso/miso"
)

func FindUser(rail miso.Rail, req FindUserReq) (UserInfo, error) {
	var r miso.GnResp[UserInfo]
	err := miso.NewDynTClient(rail, "/remote/user/info", "user-vault").
		PostJson(req).
		Json(&r)
	if err != nil {
		return UserInfo{}, fmt.Errorf("failed to find user (user-vault), %v", err)
	}
	return r.Res()
}

func FindUserId(rail miso.Rail, username string) (int, error) {
	var r miso.GnResp[int]
	err := miso.NewDynTClient(rail, "/remote/user/id", "user-vault").
		AddQueryParams("username", username).
		Get().
		Json(&r)
	if err != nil {
		return 0, fmt.Errorf("failed to findUserId (user-vault), %v", err)
	}
	return r.Res()
}

func FetchUsernames(rail miso.Rail, req FetchNameByUserNoReq) (FetchUsernamesRes, error) {
	var r miso.GnResp[FetchUsernamesRes]
	err := miso.NewDynTClient(rail, "/remote/user/userno/username", "user-vault").
		PostJson(req).
		Json(&r)
	if err != nil {
		return FetchUsernamesRes{}, fmt.Errorf("failed to fetch usernames (user-vault), %v", err)
	}
	return r.Res()
}

func FetchUsersWithRole(rail miso.Rail, req FetchUsersWithRoleReq) ([]UserInfo, error) {
	var r miso.GnResp[[]UserInfo]
	err := miso.NewDynTClient(rail, "/remote/user/list/with-role", "user-vault").
		PostJson(req).
		Json(&r)
	if err != nil {
		return nil, fmt.Errorf("failed to ListUsersWithRole, %w", err)
	}
	return r.Res()
}

func GetRoleInfo(rail miso.Rail, roleNo string) (RoleInfoResp, error) {
	var r miso.GnResp[RoleInfoResp]
	err := miso.NewDynTClient(rail, "/open/api/role/info", "user-vault").
		PostJson(RoleInfoReq{RoleNo: roleNo}).
		Json(&r)
	if err != nil {
		return RoleInfoResp{}, fmt.Errorf("failed to GetRoleInfo, %w", err)
	}
	return r.Res()
}
