package vault

import (
	"testing"
	"time"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/miso"
	"github.com/sirupsen/logrus"
)

func preTest(t *testing.T) miso.Rail {
	logrus.SetLevel(logrus.DebugLevel)
	rail := miso.EmptyRail()
	miso.DefaultReadConfig([]string{"configFile=../app-conf-dev.yml"}, rail)
	return rail
}

func preUserTest(t *testing.T) miso.Rail {
	rail := preTest(t)
	miso.TestIsNil(t, miso.InitMySQLFromProp())
	_, e := miso.GetConsulClient()
	miso.TestIsNil(t, e)
	_, e = miso.InitRedisFromProp(rail)
	miso.TestIsNil(t, e)
	return rail
}

func TestExtractSpringSalt(t *testing.T) {
	salt := extractSpringSalt("{asdfasdfasdf}sadkfasdfasdf")
	miso.TestEqual(t, "{asdfasdfasdf}", salt)
}

func TestCheckPassword(t *testing.T) {
	pw := ""
	ok := checkPassword("d7030adc17d5623265162432398c9d25dd14fd8cf3ddc9504b149e590cbacd73", "30689", pw)
	miso.TestTrue(t, ok)
}

func TestCheckUserKey(t *testing.T) {
	rail := preUserTest(t)

	userKey := "09uEo2EOsJOfqPLVCJitcdOn8BIfhUNrWtVPh7sZKVyF3140NJKb2mXRgisyRoBr"
	userId := 3
	ok, err := checkUserKey(rail, miso.GetMySQL(), userId, userKey)
	miso.TestIsNil(t, err)
	miso.TestTrue(t, ok)
}

func TestUserLogin(t *testing.T) {
	rail := preUserTest(t)
	uname := "banana"
	pword := "12345678"

	usr, err := userLogin(rail, miso.GetMySQL(), uname, pword)
	miso.TestIsNil(t, err)
	t.Logf("user: %+v", usr)

	tkn, err := buildToken(TokenUser{
		Id:       usr.Id,
		UserNo:   usr.UserNo,
		Username: usr.Username,
		RoleNo:   usr.RoleNo,
	}, time.Minute*15)
	miso.TestIsNil(t, err)
	t.Logf("tkn: %+v", tkn)

	decoded, err := miso.JwtDecode(tkn)
	miso.TestIsNil(t, err)
	t.Logf("decoded: %+v", decoded)

	tu, err := DecodeTokenUser(rail, tkn)
	if err != nil {
		t.Fatal(err)
	}
	rail.Infof("tokenUser: %+v", tu)
}

func TestAdminAddUser(t *testing.T) {
	rail := preUserTest(t)
	e := AddUser(rail, miso.GetMySQL(), AddUserParam{
		Username: "dummydummy2",
		Password: "12345678",
		RoleNo:   "role_628043111874560208429",
	}, "Test")
	miso.TestIsNil(t, e)
}

func TestListUsers(t *testing.T) {
	rail := preUserTest(t)
	users, err := ListUsers(rail, miso.GetMySQL(), ListUserReq{})
	miso.TestIsNil(t, err)
	t.Logf("%+v", users)
}

func TestAdminUpdateUser(t *testing.T) {
	rail := preUserTest(t)
	err := AdminUpdateUser(rail, miso.GetMySQL(), AdminUpdateUserReq{
		Id:         1107,
		RoleNo:     "role_628043111874560208429",
		IsDisabled: 0,
	}, common.NilUser())
	miso.TestIsNil(t, err)
}

func TestReviewUserRegistration(t *testing.T) {
	rail := preUserTest(t)
	err := ReviewUserRegistration(rail, miso.GetMySQL(), AdminReviewUserReq{
		UserId:       1107,
		ReviewStatus: ReviewApproved,
	})
	miso.TestIsNil(t, err)
}

func TestLoadUserInfoBrief(t *testing.T) {
	rail := preUserTest(t)
	uib, err := LoadUserInfoBrief(rail, miso.GetMySQL(), "dummydummy2")
	miso.TestIsNil(t, err)
	t.Logf("uib: %+v", uib)
}
