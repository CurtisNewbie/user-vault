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

// Retrieve role information
func GetRoleInfo(rail miso.Rail, req RoleInfoReq) (*RoleInfoResp, error) {
	tr := miso.NewDynTClient(rail, "/remote/role/info", "goauth").
		EnableTracing().
		PostJson(req)

	if tr.Err != nil {
		return nil, tr.Err
	}

	if err := tr.Require2xx(); err != nil {
		return nil, err
	}

	r, e := miso.ReadGnResp[*RoleInfoResp](tr)
	if e != nil {
		return nil, e
	}

	if r.Error {
		return nil, r.Err()
	}

	if r.Data == nil {
		return nil, errors.New("data is nil, unable to retrieve RoleInfoResp")
	}

	return r.Data, nil
}
