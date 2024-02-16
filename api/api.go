package api

import "github.com/curtisnewbie/miso/miso"

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

type FetchNameByUserNoReq struct {
	UserNos []string `json:"userNos"`
}

type FetchUsernamesRes struct {
	UserNoToUsername map[string]string `json:"userNoToUsername"`
}

type FetchUsersWithRoleReq struct {
	RoleNo string `valid:"notEmpty"`
}

type RoleInfoReq struct {
	RoleNo string `json:"roleNo" validation:"notEmpty"`
}

type RoleInfoResp struct {
	RoleNo string `json:"roleNo"`
	Name   string `json:"name"`
}
