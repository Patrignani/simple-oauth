package oauth

import (
	"context"

	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	jwt "github.com/golang-jwt/jwt/v5"
)

type fiberContext struct {
	*fiber.Ctx
}

func (c fiberContext) Body() ([]byte, error) {
	return c.Ctx.Body(), nil
}

func (c fiberContext) JSON(code int, i interface{}) error {
	return c.Status(code).JSON(i)
}

func (c fiberContext) String(code int, s string) error {
	return c.Status(code).SendString(s)
}

func (c fiberContext) RequestContext() context.Context {
	return c.Context()
}

func (c fiberContext) Header(key string) string {
	return c.Get(key)
}

func (a *Authorization) FiberHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return a.LoginOAuth(fiberContext{c})
	}
}

func (a *Authorization) GetFiberDefaultMiddleWareJwtValidate() fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key: []byte(a.options.Key),
		},
	})
}

func (a *Authorization) FiberRolesMiddleware(roleList ...RolesPermissions) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userToken := c.Locals("user").(*jwt.Token)
		claims := userToken.Claims.(jwt.MapClaims)

		if !hasRoleFromClaims(claims, roleList...) {
			return fiber.ErrForbidden
		}

		if a.authConfigure != nil && a.authConfigure.CustomActionRolesMiddleware != nil {
			if err := a.authConfigure.CustomActionRolesMiddleware(fiberContext{c}, userToken, claims); err != nil {
				return err
			}
		}

		return c.Next()
	}
}

func hasRoleFromClaims(claims jwt.MapClaims, roleList ...RolesPermissions) bool {
	userRoles := []string{}

	if rawRoles, ok := claims["roles"]; ok && rawRoles != nil {
		switch v := rawRoles.(type) {
		case []interface{}:
			for _, r := range v {
				if rs, ok := r.(string); ok {
					userRoles = append(userRoles, rs)
				}
			}
		case []string:
			userRoles = append(userRoles, v...)
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
