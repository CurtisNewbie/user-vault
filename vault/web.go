package vault

import (
	"github.com/curtisnewbie/gocommon/common"
	"github.com/curtisnewbie/gocommon/goauth"
	"github.com/curtisnewbie/miso/core"
	"github.com/curtisnewbie/miso/mysql"
	"github.com/curtisnewbie/miso/server"
	"github.com/gin-gonic/gin"
)

const (
	headerForwardedFor = "X-Forwarded-For"
	headerUserAgent    = "User-Agent"

	passwordLoginUrl = "/user-vault/open/api/user/login"
)

type LoginReq struct {
	Username string `json:"username" valid:"notEmpty"`
	Password string `json:"password" valid:"notEmpty"`
}

type AddUserReq struct {
	Username string `json:"username" valid:"notEmpty"`
	Password string `json:"password" valid:"notEmpty"`
	RoleNo   string `json:"roleNo" valid:"notEmpty"`
}

func registerRoutes(rail core.Rail) error {

	server.IPost("/open/api/user/login",
		func(gin *gin.Context, rail core.Rail, req LoginReq) (string, error) {
			token, err := UserLogin(rail, mysql.GetConn(), PasswordLoginParam(req))
			if err != nil {
				return "", err
			}

			remoteAddr := RemoteAddr(gin.GetHeader(headerForwardedFor))
			userAgent := gin.GetHeader(headerUserAgent)

			if er := sendAccessLogEvnet(rail, AccessLogEvent{
				IpAddress:  remoteAddr,
				UserAgent:  userAgent,
				UserId:     0, // TODO: remove this field
				Username:   req.Username,
				Url:        passwordLoginUrl,
				AccessTime: core.Now(),
			}); er != nil {
				rail.Errorf("Failed to sendAccessLogEvent, username: %v, remoteAddr: %v, userAgent: %v, %v",
					req.Username, remoteAddr, userAgent, er)
			}

			return token, err
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Login", Type: goauth.PT_PUBLIC}),
	)

	server.IPost[AddUserParam, any]("/open/api/user/add",
		func(c *gin.Context, rail core.Rail, req AddUserParam) (any, error) {
			return nil, AddUser(rail, mysql.GetConn(), AddUserParam(req), common.GetUser(rail))
		})

	return nil
}
