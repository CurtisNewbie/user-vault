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
)

type LoginWebVo struct {
	Username string `json:"username" valid:"notEmpty"`
	Password string `json:"password" valid:"notEmpty"`
}

func registerRoutes(rail core.Rail) error {

	server.IPost("/open/api/login",
		func(gin *gin.Context, rail core.Rail, req LoginWebVo) (string, error) {
			remoteAddr := RemoteAddr(gin.GetHeader(headerForwardedFor))
			userAgent := gin.GetHeader(headerUserAgent)
			token, err := UserLogin(rail, mysql.GetConn(), PasswordLoginReq{
				RemoteAddr: remoteAddr,
				UserAgent:  userAgent,
				Username:   req.Username,
				Password:   req.Password,
			})
			return token, err
		},
		goauth.PathDocExtra(goauth.PathDoc{Desc: "Login", Type: goauth.PT_PUBLIC}),
	)

	return nil
}
