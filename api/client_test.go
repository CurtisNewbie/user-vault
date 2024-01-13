package api

import (
	"testing"

	"github.com/curtisnewbie/miso/miso"
)

func _apiPreTest(t *testing.T) miso.Rail {
	miso.SetProp(miso.PropAppName, "test")
	miso.SetProp("client.addr.user-vault.host", "localhost")
	miso.SetProp("client.addr.user-vault.port", "8089")
	miso.SetProp(miso.PropConsulEnabled, true)
	return miso.EmptyRail()
}

func TestFindUser(t *testing.T) {
	// miso.SetLogLevel("debug")
	rail := _apiPreTest(t)
	name := "admin"
	ui, err := FindUser(rail, FindUserReq{
		Username: &name,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("UserInfo: %+v", ui)
}

func TestFindUserId(t *testing.T) {
	// miso.SetLogLevel("debug")
	rail := _apiPreTest(t)
	id, err := FindUserId(rail, "admin")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("id: %v", id)
}

func TestFetchUsernames(t *testing.T) {
	// miso.SetLogLevel("debug")
	rail := _apiPreTest(t)
	res, err := FetchUsernames(rail, FetchUsernameReq{
		UserNos: []string{"UE1049787455160320075953"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("res: %+v", res)
}
