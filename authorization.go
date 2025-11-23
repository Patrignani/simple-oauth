package oauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Authorization struct {
	authConfigure *OAuthConfigure
	options       *OAuthSimpleOption
}

func NewAuthorization(c *OAuthConfigure, s *OAuthSimpleOption) *Authorization {
	return &Authorization{c, s}
}

func (a *Authorization) LoginOAuth(c HttpContext) error {
	authBasic := new(OAuthBasic)

	body, err := c.Body()
	if err != nil {
		return c.String(http.StatusBadRequest, "Bad request")
	}

	if err := json.Unmarshal(body, &authBasic); err != nil {
		_ = c.JSON(http.StatusBadRequest, "Error decode "+err.Error())
		return err
	}

	bodyReader := bytes.NewReader(body)

	if len(authBasic.Grant_type) == 0 {
		errMsg := "empty grant_type"
		_ = c.JSON(http.StatusBadRequest, errMsg)
		return errors.New(errMsg)
	}

	switch strings.ToLower(authBasic.Grant_type) {

	case "password":
		pass := new(OAuthPassword)
		if err := json.NewDecoder(bodyReader).Decode(&pass); err != nil {
			_ = c.JSON(http.StatusBadRequest,
				"Request body is invalid due to the type of the grant_type. "+err.Error())
			return err
		}

		roles := a.authConfigure.PasswordAuthorization(c, pass)
		a.CreateResponsePassword(roles, c)

	case "client_credentials":
		client := new(OAuthClient)
		if err := json.NewDecoder(bodyReader).Decode(&client); err != nil {
			_ = c.JSON(http.StatusBadRequest,
				"Request body is invalid due to the type of the grant_type. "+err.Error())
			return err
		}

		roles := a.authConfigure.ClientCredentialsAuthorization(c, client)
		a.CreateResponseClient(roles, c)

	case "refresh_token":
		refresh := new(OAuthRefreshToken)
		if err := json.NewDecoder(bodyReader).Decode(&refresh); err != nil {
			_ = c.JSON(http.StatusBadRequest,
				"Request body is invalid due to the type of the grant_type. "+err.Error())
			return err
		}

		roles := a.authConfigure.RefreshTokenCredentialsAuthorization(c, refresh)
		a.CreateResponsePassword(roles.AuthorizationRolesPassword, c)

	default:
		errMsg := "invalid grant_type"
		_ = c.JSON(http.StatusBadRequest, errMsg)
		return errors.New(errMsg)
	}

	return nil
}

func (a *Authorization) CreateResponseClient(authorizationRolesClient AuthorizationRolesClient, c HttpContext) {
	if authorizationRolesClient.Authorized {
		expire := time.Now().Add(time.Minute * time.Duration(a.options.ExpireTimeMinutesClient))
		token, err := a.GenerateToken(authorizationRolesClient.AuthorizationRolesBasic, expire)
		if err != nil {
			_ = c.JSON(http.StatusBadRequest, err)
			return
		}

		result := AuthorizationClientPass{
			AuthorizationBasic{
				Access_token: *token,
				Token_type:   "Bearer",
				Expires_in:   expire.Format("2006-01-02 15:04:05"),
			},
		}

		_ = c.JSON(http.StatusOK, result)
		return
	}

	_ = c.JSON(http.StatusUnauthorized, "")
}

func (a *Authorization) CreateResponsePassword(authorizationRoles AuthorizationRolesPassword, c HttpContext) {
	if authorizationRoles.Authorized {
		expire := time.Now().Add(time.Minute * time.Duration(a.options.ExpireTimeMinutes))
		token, err := a.GenerateToken(authorizationRoles.AuthorizationRolesBasic, expire)
		if err != nil {
			_ = c.JSON(http.StatusBadRequest, err)
			return
		}

		result := AuthorizationRefreshPass{
			AuthorizationBasic{
				Access_token: *token,
				Token_type:   "Bearer",
				Expires_in:   expire.Format("2006-01-02 15:04:05"),
			},
			authorizationRoles.RefreshToken,
		}

		_ = c.JSON(http.StatusOK, result)
		return
	}

	_ = c.JSON(http.StatusUnauthorized, "")
}

func (a *Authorization) GenerateToken(authBasic AuthorizationRolesBasic, expiresAt time.Time) (*string, error) {
	claims := jwt.MapClaims{
		"roles":    authBasic.Roles,
		"subject":  authBasic.Subject,
		"audience": a.options.Audience,
		"issuer":   a.options.Issuer,
		"exp":      jwt.NewNumericDate(expiresAt),
		"iat":      time.Now().Unix(),
	}

	if len(authBasic.Claims) > 0 {
		for key, value := range authBasic.Claims {
			claims[key] = value
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte(a.options.Key))
	if err != nil {
		return nil, err
	}

	return &t, nil
}
