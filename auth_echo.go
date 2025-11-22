package oauth

import (
	"io"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

type echoContext struct {
	echo.Context
}

func (c echoContext) Body() ([]byte, error) {
	return io.ReadAll(c.Request().Body)
}

func (a *Authorization) EchoHandler() echo.HandlerFunc {
	return func(c echo.Context) error {
		return a.LoginOAuth(echoContext{c})
	}
}

func (a *Authorization) GetEchoDefaultMiddleWareJwtValidate() echo.MiddlewareFunc {
	return a.GetEchoMiddleWareJwtValidate(echojwt.Config{
		SigningMethod: "HS256",
		SigningKey:    []byte(a.options.Key),
	})
}

func (a *Authorization) GetEchoMiddleWareJwtValidate(opt echojwt.Config) echo.MiddlewareFunc {
	return echojwt.WithConfig(opt)
}

func hasRole(claims jwt.MapClaims, roleList ...RolesPermissions) bool {
	userRoles := []string{}

	if claims["roles"] != nil {
		if roles, ok := claims["roles"].([]interface{}); ok {
			for _, role := range roles {
				if r, ok := role.(string); ok {
					userRoles = append(userRoles, r)
				}
			}
		}
	}

	for _, role := range userRoles {
		for _, r := range roleList {
			if role == string(r) {
				return true
			}
		}
	}
	return false
}

func (a *Authorization) EchoRolesMiddleware(roleList ...RolesPermissions) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user := c.Get("user").(*jwt.Token)
			claims := user.Claims.(jwt.MapClaims)

			if !hasRole(claims, roleList...) {
				return echo.ErrForbidden
			}

			if a.authConfigure != nil && a.authConfigure.CustomActionRolesMiddleware != nil {
				if err := a.authConfigure.CustomActionRolesMiddleware(user, claims); err != nil {
					return err
				}
			}

			return next(c)
		}
	}
}
