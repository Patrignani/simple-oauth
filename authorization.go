package oauth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
)

type Authorization struct {
	authConfigure *OAuthConfigure
	options       *OAuthSimpleOption
	e             *echo.Echo
}

func NewAuthorization(c *OAuthConfigure, s *OAuthSimpleOption, e *echo.Echo) *Authorization {
	return &Authorization{c, s, e}
}

func (a *Authorization) CreateAuthRouter() {
	authRouter := a.e.Group(a.options.AuthRouter)
	authRouter.POST("/", a.LoginOAuth)
}

func (a *Authorization) LoginOAuth(c echo.Context) error {
	grantType := ""

	err := echo.QueryParamsBinder(c).
		String("grant_type", &grantType).
		BindError()

	if err != nil {
		c.JSON(http.StatusBadRequest, err)
		return err
	}

	if len(grantType) == 0 {
		errorValue := "empty grant_type"
		c.JSON(http.StatusBadRequest, errorValue)
		return errors.New(errorValue)
	}

	switch strings.ToLower(grantType) {
	case "password":
		pass := new(OAuthPassword)
		if err := c.Bind(pass); err != nil {
			c.JSON(http.StatusBadRequest, "Request body is invalid due to the type of the grant_type. "+err.Error())
			return err
		}
		roles := a.authConfigure.PasswordAuthorization(pass)
		a.CreateResponsePassword(roles, c)
	case "client_credentials":
		client := new(OAuthClient)
		if err := c.Bind(client); err != nil {
			c.JSON(http.StatusBadRequest, "Request body is invalid due to the type of the grant_type. "+err.Error())
			return err
		}
		roles := a.authConfigure.ClientCredentialsAuthorization(client)
		a.CreateResponseClient(roles, c)
	case "refresh_token":
		refresh := new(OAuthRefreshToken)
		if err := c.Bind(refresh); err != nil {
			c.JSON(http.StatusBadRequest, "Request body is invalid due to the type of the grant_type. "+err.Error())
			return err
		}
		roles := a.authConfigure.RefreshTokenCredentialsAuthorization(refresh)
		a.CreateResponsePassword(roles.AuthorizationRolesPassword, c)
	default:
		errorValue := "invalid grant_type"
		c.JSON(http.StatusBadRequest, errorValue)
		return errors.New(errorValue)
	}

	return nil
}

func (a *Authorization) CreateResponseClient(authorizationRolesClient AuthorizationRolesClient, c echo.Context) {
	if authorizationRolesClient.Authorized {
		expire := time.Now().Add(time.Minute * time.Duration(a.options.ExpireTimeMinutes))
		token, err := a.GenerateToken(authorizationRolesClient.AuthorizationRolesBasic, expire)

		if err != nil {
			c.JSON(http.StatusBadRequest, err)
		}

		result := AuthorizationClientPass{
			AuthorizationBasic{
				Access_token: *token,
				Token_type:   "Bearer",
				Expires_in:   expire.Format("2006-01-02 15:04:05"),
			},
		}

		c.JSON(http.StatusOK, result)
	} else {
		c.JSON(http.StatusUnauthorized, "")
	}
}

func (a *Authorization) CreateResponsePassword(authorizationRoles AuthorizationRolesPassword, c echo.Context) {

	if authorizationRoles.Authorized {
		expire := time.Now().Add(time.Minute * time.Duration(a.options.ExpireTimeMinutes))
		token, err := a.GenerateToken(authorizationRoles.AuthorizationRolesBasic, expire)

		if err != nil {
			c.JSON(http.StatusBadRequest, err)
		}

		result := AuthorizationRefreshPass{

			AuthorizationBasic{
				Access_token: *token,
				Token_type:   "Bearer",
				Expires_in:   expire.Format("2006-01-02 15:04:05"),
			},
			authorizationRoles.RefreshToken,
		}

		c.JSON(http.StatusOK, result)
	} else {
		c.JSON(http.StatusUnauthorized, "")
	}

}

func (a *Authorization) GenerateToken(authBasic AuthorizationRolesBasic, expiresAt time.Time) (*string, error) {
	claims := AuthClaims{
		authBasic.Claims,
		authBasic.Roles,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    a.options.Issuer,
			Audience:  a.options.Audience,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte(a.options.Key))
	if err != nil {
		return nil, err
	}

	return &t, nil
}
