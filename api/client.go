package api

import (
	"fmt"

	"github.com/curtisnewbie/miso/miso"
)

type FindUserReq struct {
	UserId   *int    `json:"userId"`
	UserNo   *string `json:"userNo"`
	Username *string `json:"username"`
}

type UserInfo struct {
	Id         int        `json:"id"`
	Username   string     `json:"username"`
	RoleName   string     `json:"roleName"`
	RoleNo     string     `json:"roleNo"`
	UserNo     string     `json:"userNo"`
	IsDisabled int        `json:"isDisabled"`
	CreateTime miso.ETime `json:"createTime"`
	CreateBy   string     `json:"createBy"`
	UpdateTime miso.ETime `json:"updateTime"`
	UpdateBy   string     `json:"updateBy"`
}

func FindUser(rail miso.Rail, req FindUserReq) (UserInfo, error) {
	var r miso.GnResp[UserInfo]
	err := miso.NewDynTClient(rail, "/remote/user/info", "user-vault").
		Require2xx().
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
		Require2xx().
		AddQueryParams("username", username).
		Get().
		Json(&r)
	if err != nil {
		return 0, fmt.Errorf("failed to findUserId (user-vault), %v", err)
	}
	return r.Res()
}

type FetchUsernameReq struct {
	UserNos []string `json:"userNos"`
}

type FetchUsernamesRes struct {
	UserNoToUsername map[string]string `json:"userNoToUsername"`
}

func FetchUsernames(rail miso.Rail, req FetchUsernameReq) (FetchUsernamesRes, error) {
	var r miso.GnResp[FetchUsernamesRes]
	err := miso.NewDynTClient(rail, "/remote/user/userno/username", "user-vault").
		Require2xx().
		PostJson(req).
		Json(&r)
	if err != nil {
		return FetchUsernamesRes{}, fmt.Errorf("failed to fetch usernames (user-vault), %v", err)
	}
	return r.Res()
}
