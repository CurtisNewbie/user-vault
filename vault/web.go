package vault

import (
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

func registerRoutes(rail core.Rail) error {

	server.IPost("/open/api/login",
		func(gin *gin.Context, rail core.Rail, req LoginReq) (string, error) {
			token, err := UserLogin(rail, mysql.GetConn(), PasswordLoginReq(req))
			if err != nil {
				return "", err
			}

			remoteAddr := RemoteAddr(gin.GetHeader(headerForwardedFor))
			userAgent := gin.GetHeader(headerUserAgent)

			if er := sendAccessLogEvnet(rail, AccessLogEvent{
				IpAddress: remoteAddr,
				UserAgent: userAgent,
				UserId:    0, // TODO: remove this field
				Username:  req.Username,
				Url:       passwordLoginUrl,
				AccessTime: core.Now(),
			}); er != nil {
				rail.Errorf("Failed to sendAccessLogEvent, username: %v, remoteAddr: %v, userAgent: %v, %v",
					req.Username, remoteAddr, userAgent, er)
			}

			return token, err
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Login", Type: goauth.PT_PUBLIC}),
	)

	return nil
}
