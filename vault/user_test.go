package vault

import (
	"testing"

	"github.com/curtisnewbie/miso/core"
	"github.com/curtisnewbie/miso/jwt"
	"github.com/curtisnewbie/miso/mysql"
	"github.com/sirupsen/logrus"
)

func userPreTest(t *testing.T) core.Rail {
	logrus.SetLevel(logrus.DebugLevel)
	rail := core.EmptyRail()
	core.DefaultReadConfig([]string{"configFile=../app-conf-dev.yml"}, rail)
	core.TestIsNil(t, mysql.InitMySqlFromProp())
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
	rail := userPreTest(t)

	userKey := "09uEo2EOsJOfqPLVCJitcdOn8BIfhUNrWtVPh7sZKVyF3140NJKb2mXRgisyRoBr"
	userId := 3
	ok, err := checkUserKey(rail, mysql.GetConn(), userId, userKey)
	core.TestIsNil(t, err)
	core.TestTrue(t, ok)
}

func TestUserLogin(t *testing.T) {
	rail := userPreTest(t)
	uname := ""
	pword := ""

	usr, err := userLogin(rail, mysql.GetConn(), uname, pword)
	core.TestIsNil(t, err)
	t.Logf("user: %+v", usr)

	tkn, err := buildToken(usr)
	core.TestIsNil(t, err)
	t.Logf("tkn: %+v", tkn)

	decoded, err := jwt.DecodeToken(tkn)
	core.TestIsNil(t, err)
	t.Logf("decoded: %+v", decoded)
}
