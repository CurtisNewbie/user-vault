package vault

import (
	"errors"

	"github.com/curtisnewbie/miso/miso"
)

type RoleInfoReq struct {
	RoleNo string `json:"roleNo" `
}

type RoleInfoResp struct {
	RoleNo string `json:"roleNo"`
	Name   string `json:"name"`
}

func GetRoleInfo(rail miso.Rail, req RoleInfoReq) (*RoleInfoResp, error) {
	var res miso.GnResp[*RoleInfoResp]
	err := miso.NewDynTClient(rail, "/remote/role/info", "goauth").
		PostJson(req).
		Json(&res)
	if err != nil {
		return nil, err
	}

	rir, err := res.Res()
	if err != nil {
		return nil, err
	}
	if rir == nil {
		return nil, errors.New("data is nil, unable to retrieve RoleInfoResp")
	}
	return rir, nil
}
