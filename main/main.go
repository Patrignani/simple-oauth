package main

import (
	oauth "github.com/Patrignani/simple-oauth"
	"github.com/labstack/echo/v4"
)

func main() {
	options := &oauth.OAuthSimpleOption{
		Key:               "teste",
		ExpireTimeMinutes: 20,
		AuthRouter:        "/Auth",
	}

	authConfigure := &oauth.OAuthConfigure{
		ClientCredentialsAuthorization: func(client *oauth.OAuthClient) oauth.AuthorizationRolesClient {
			return oauth.AuthorizationRolesClient{}
		},
	}

	e := echo.New()

	authRouter := oauth.NewAuthorization(authConfigure, options, e)

	authRouter.CreateAuthRouter()

	e.Logger.Fatal(e.Start(":8001"))

}
