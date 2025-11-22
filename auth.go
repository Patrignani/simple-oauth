package oauth

import (
	jwt "github.com/golang-jwt/jwt/v5"
)

type RolesPermissions string

type OAuthBasic struct {
	Grant_type    string `json:"grant_type"`
	Client_id     string `json:"client_id"`
	Client_secret string `json:"client_secret"`
}

type AuthorizationBasic struct {
	Token_type   string `json:"token_type"`
	Expires_in   string `json:"expires_in"`
	Access_token string `json:"access_token"`
}

type AuthorizationClientPass struct {
	AuthorizationBasic
}

type AuthorizationRefreshPass struct {
	AuthorizationBasic
	Refresh_token string `json:"refresh_token"`
}

type OAuthPassword struct {
	OAuthBasic
	Username string `json:"username"`
	Password string `json:"password"`
}

type OAuthClient struct {
	OAuthBasic
}

type OAuthRefreshToken struct {
	OAuthBasic
	Refresh_token string `json:"refresh_token"`
}

type AuthorizationRolesBasic struct {
	Authorized bool              `json:"authorized"`
	Claims     map[string]string `json:"claims,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Subject    string            `json:"subject,omitempty"`
}

type AuthorizationRolesPassword struct {
	AuthorizationRolesBasic
	RefreshToken string `json:"refresh_token"`
}

type AuthorizationRolesClient struct {
	AuthorizationRolesBasic
}

type AuthorizationRolesRefresh struct {
	AuthorizationRolesPassword
}

type OAuthConfigure struct {
	PasswordAuthorization                func(pass *OAuthPassword) AuthorizationRolesPassword
	ClientCredentialsAuthorization       func(client *OAuthClient) AuthorizationRolesClient
	RefreshTokenCredentialsAuthorization func(refresh *OAuthRefreshToken) AuthorizationRolesRefresh

	CustomActionRolesMiddleware func(token *jwt.Token, claims jwt.MapClaims) error
}

type OAuthSimpleOption struct {
	Key                     string   `json:"key"`
	Audience                []string `json:"audience"`
	ExpireTimeMinutes       int      `json:"expire_time_minutes"`
	ExpireTimeMinutesClient int      `json:"expire_time_minutes_client"`
	Issuer                  string   `json:"Issuer"`
	AuthRouter              string   `json:"auth_router"`
}
