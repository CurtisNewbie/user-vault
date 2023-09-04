package vault

import (
	"testing"
	"time"

	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/miso/consul"
	"github.com/curtisnewbie/miso/core"
	"github.com/curtisnewbie/miso/jwt"
	"github.com/curtisnewbie/miso/mysql"
	"github.com/curtisnewbie/miso/redis"
	"github.com/sirupsen/logrus"
)

func preTest(t *testing.T) core.Rail {
	logrus.SetLevel(logrus.DebugLevel)
	rail := core.EmptyRail()
	core.DefaultReadConfig([]string{"configFile=../app-conf-dev.yml"}, rail)
	return rail
}

func preUserTest(t *testing.T) core.Rail {
	rail := preTest(t)
	core.TestIsNil(t, mysql.InitMySqlFromProp())
	_, e := consul.GetConsulClient()
	core.TestIsNil(t, e)
	_, e = redis.InitRedisFromProp()
	core.TestIsNil(t, e)
	return rail
}

func TestExtractSpringSalt(t *testing.T) {
	salt := extractSpringSalt("{asdfasdfasdf}sadkfasdfasdf")
	core.TestEqual(t, "{asdfasdfasdf}", salt)
}

func TestCheckPassword(t *testing.T) {
	pw := ""
	ok := checkPassword("d7030adc17d5623265162432398c9d25dd14fd8cf3ddc9504b149e590cbacd73", "30689", pw)
	core.TestTrue(t, ok)
}

func TestCheckUserKey(t *testing.T) {
	rail := preUserTest(t)

	userKey := "09uEo2EOsJOfqPLVCJitcdOn8BIfhUNrWtVPh7sZKVyF3140NJKb2mXRgisyRoBr"
	userId := 3
	ok, err := checkUserKey(rail, mysql.GetConn(), userId, userKey)
	core.TestIsNil(t, err)
	core.TestTrue(t, ok)
}

func TestUserLogin(t *testing.T) {
	rail := preUserTest(t)
	uname := ""
	pword := ""

	usr, err := userLogin(rail, mysql.GetConn(), uname, pword)
	core.TestIsNil(t, err)
	t.Logf("user: %+v", usr)

	tkn, err := buildToken(usr, time.Minute*15)
	core.TestIsNil(t, err)
	t.Logf("tkn: %+v", tkn)

	decoded, err := jwt.DecodeToken(tkn)
	core.TestIsNil(t, err)
	t.Logf("decoded: %+v", decoded)
}

func TestAdminAddUser(t *testing.T) {
	rail := preUserTest(t)
	e := AddUser(rail, mysql.GetConn(), AddUserParam{
		Username: "dummydummy2",
		Password: "12345678",
		RoleNo:   "role_628043111874560208429",
	}, "Test")
	core.TestIsNil(t, e)
}

func TestListUsers(t *testing.T) {
	rail := preUserTest(t)
	users, err := ListUsers(rail, mysql.GetConn(), ListUserReq{})
	core.TestIsNil(t, err)
	t.Logf("%+v", users)
}

func TestAdminUpdateUser(t *testing.T) {
	rail := preUserTest(t)
	err := AdminUpdateUser(rail, mysql.GetConn(), AdminUpdateUserReq{
		Id:         1107,
		RoleNo:     "role_628043111874560208429",
		IsDisabled: 0,
	}, common.NilUser())
	core.TestIsNil(t, err)
}

func TestReviewUserRegistration(t *testing.T) {
	rail := preUserTest(t)
	err := ReviewUserRegistration(rail, mysql.GetConn(), AdminReviewUserReq{
		UserId:       1107,
		ReviewStatus: ReviewApproved,
	})
	core.TestIsNil(t, err)
}

func TestLoadUserInfoBrief(t *testing.T) {
	rail := preUserTest(t)
	uib, err := LoadUserInfoBrief(rail, mysql.GetConn(), "dummydummy2")
	core.TestIsNil(t, err)
	t.Logf("uib: %+v", uib)
}
