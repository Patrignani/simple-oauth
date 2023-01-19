package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
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

func (a *Authorization) CreateAuthRouter() *echo.Group {
	authRouter := a.e.Group(a.options.AuthRouter)
	authRouter.POST("", a.LoginOAuth)

	return authRouter
}

func (a *Authorization) LoginOAuth(c echo.Context) error {
	authBasic := new(OAuthBasic)

	body, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		return c.String(http.StatusBadRequest, "Bad request")
	}

	if err := json.Unmarshal(body, &authBasic); err != nil {
		c.JSON(http.StatusBadRequest, "Error decode "+err.Error())
		return err
	}

	bodyReader := bytes.NewReader(body)

	if len(authBasic.Grant_type) == 0 {
		errorValue := "empty grant_type"
		c.JSON(http.StatusBadRequest, errorValue)
		return errors.New(errorValue)
	}

	switch strings.ToLower(authBasic.Grant_type) {
	case "password":
		pass := new(OAuthPassword)
		if err := json.NewDecoder(bodyReader).Decode(&pass); err != nil {
			c.JSON(http.StatusBadRequest, "Request body is invalid due to the type of the grant_type. "+err.Error())
			return err
		}
		roles := a.authConfigure.PasswordAuthorization(pass)
		a.CreateResponsePassword(roles, c)
	case "client_credentials":
		client := new(OAuthClient)
		if err := json.NewDecoder(bodyReader).Decode(&client); err != nil {
			c.JSON(http.StatusBadRequest, "Request body is invalid due to the type of the grant_type. "+err.Error())
			return err
		}
		roles := a.authConfigure.ClientCredentialsAuthorization(client)
		a.CreateResponseClient(roles, c)
	case "refresh_token":
		refresh := new(OAuthRefreshToken)
		if err := json.NewDecoder(bodyReader).Decode(&refresh); err != nil {
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
		expire := time.Now().Add(time.Minute * time.Duration(a.options.ExpireTimeMinutesClient))
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
		authBasic.Permissions,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			Issuer:    a.options.Issuer,
			Audience:  a.options.Audience,
			Subject:   authBasic.Subject,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte(a.options.Key))
	if err != nil {
		return nil, err
	}

	return &t, nil
}
