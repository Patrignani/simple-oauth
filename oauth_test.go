package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

//
// Fake HttpContext para testes
//

type fakeContext struct {
	body    []byte
	Status  int
	JSONVal interface{}
	StrVal  string
}

func newFakeContext(body []byte) *fakeContext {
	return &fakeContext{body: body}
}

func (f *fakeContext) Body() ([]byte, error) {
	return f.body, nil
}
func (f *fakeContext) JSON(code int, i interface{}) error {
	f.Status = code
	f.JSONVal = i
	return nil
}
func (f *fakeContext) String(code int, s string) error {
	f.Status = code
	f.StrVal = s
	return nil
}

// NOVOS MÉTODOS EXIGIDOS PELO HttpContext
func (f *fakeContext) RequestContext() context.Context {
	return context.Background()
}
func (f *fakeContext) Header(key string) string {
	return ""
}

//
// Teste GenerateToken
//

func TestGenerateToken_IncluiClaimsEPadrao(t *testing.T) {
	opts := &OAuthSimpleOption{
		Key:      "secret-key",
		Audience: []string{"aud1"},
		Issuer:   "issuer-test",
	}

	auth := NewAuthorization(nil, opts)

	expiresAt := time.Now().Add(30 * time.Minute)
	roles := []string{"ADMIN", "USER"}
	customClaims := map[string]string{"foo": "bar", "env": "test"}

	tokenStrPtr, err := auth.GenerateToken(AuthorizationRolesBasic{
		Authorized: true,
		Claims:     customClaims,
		Roles:      roles,
		Subject:    "user-123",
	}, expiresAt)
	if err != nil {
		t.Fatalf("GenerateToken retornou erro: %v", err)
	}

	tokenStr := *tokenStrPtr
	parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("método de assinatura inesperado")
		}
		return []byte(opts.Key), nil
	})
	if err != nil {
		t.Fatalf("erro ao fazer parse: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("token inválido")
	}

	claims := parsed.Claims.(jwt.MapClaims)
	if claims["subject"] != "user-123" {
		t.Errorf("subject errado: %v", claims["subject"])
	}
	if claims["issuer"] != opts.Issuer {
		t.Errorf("issuer errado: %v", claims["issuer"])
	}
	if claims["foo"] != "bar" {
		t.Errorf("claim custom inexistente: %v", claims["foo"])
	}
}

//
// LoginOAuth – PASSWORD
//

func TestLoginOAuth_PasswordGrant_Sucesso(t *testing.T) {
	var receivedPass *OAuthPassword
	var receivedCtx RequestCtx

	cfg := &OAuthConfigure{
		PasswordAuthorization: func(ctx RequestCtx, pass *OAuthPassword) AuthorizationRolesPassword {
			receivedCtx = ctx
			receivedPass = pass
			return AuthorizationRolesPassword{
				AuthorizationRolesBasic: AuthorizationRolesBasic{
					Authorized: true,
					Roles:      []string{"USER"},
					Subject:    "user-1",
				},
				RefreshToken: "refresh-123",
			}
		},
	}

	opts := &OAuthSimpleOption{
		Key:               "secret-key",
		ExpireTimeMinutes: 30,
		AuthRouter:        "/auth",
	}

	auth := NewAuthorization(cfg, opts)

	bodyMap := map[string]string{
		"grant_type": "password",
		"username":   "john",
		"password":   "doe",
	}
	bodyBytes, _ := json.Marshal(bodyMap)

	ctx := newFakeContext(bodyBytes)

	err := auth.LoginOAuth(ctx)
	if err != nil {
		t.Fatalf("erro: %v", err)
	}

	if receivedCtx == nil {
		t.Fatal("ctx não foi passado para PasswordAuthorization")
	}

	if receivedPass.Username != "john" || receivedPass.Password != "doe" {
		t.Errorf("password incorreto: %#v", receivedPass)
	}

	if ctx.Status != http.StatusOK {
		t.Errorf("status errado: %d", ctx.Status)
	}
}

//
// LoginOAuth – CLIENT CREDENTIALS
//

func TestLoginOAuth_ClientCredentials_Sucesso(t *testing.T) {
	var receivedClient *OAuthClient
	var receivedCtx RequestCtx

	cfg := &OAuthConfigure{
		ClientCredentialsAuthorization: func(ctx RequestCtx, client *OAuthClient) AuthorizationRolesClient {
			receivedCtx = ctx
			receivedClient = client
			return AuthorizationRolesClient{
				AuthorizationRolesBasic: AuthorizationRolesBasic{
					Authorized: true,
					Roles:      []string{"SERVICE"},
					Subject:    "client-1",
				},
			}
		},
	}

	opts := &OAuthSimpleOption{
		Key:                     "secret-key",
		ExpireTimeMinutesClient: 60,
		AuthRouter:              "/auth",
	}

	auth := NewAuthorization(cfg, opts)

	bodyMap := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "svc-1",
		"client_secret": "svc-secret",
	}
	bodyBytes, _ := json.Marshal(bodyMap)

	ctx := newFakeContext(bodyBytes)

	err := auth.LoginOAuth(ctx)
	if err != nil {
		t.Fatalf("erro: %v", err)
	}

	if receivedCtx == nil {
		t.Fatal("ctx não foi passado para ClientCredentialsAuthorization")
	}

	if receivedClient == nil {
		t.Fatalf("ClientCredentialsAuthorization não foi chamado")
	}

	if ctx.Status != http.StatusOK {
		t.Errorf("status errado: %d", ctx.Status)
	}
}

//
// LoginOAuth – invalid
//

func TestLoginOAuth_GrantTypeInvalido(t *testing.T) {
	cfg := &OAuthConfigure{}
	opts := &OAuthSimpleOption{
		Key: "secret-key",
	}

	auth := NewAuthorization(cfg, opts)

	bodyMap := map[string]string{
		"grant_type": "invalid",
	}
	bodyBytes, _ := json.Marshal(bodyMap)

	ctx := newFakeContext(bodyBytes)

	err := auth.LoginOAuth(ctx)
	if err == nil {
		t.Fatal("esperado erro e não veio")
	}

	if ctx.Status != http.StatusBadRequest {
		t.Errorf("status esperado %d, got %d", http.StatusBadRequest, ctx.Status)
	}
}

func TestLoginOAuth_GrantTypeVazio(t *testing.T) {
	cfg := &OAuthConfigure{}
	opts := &OAuthSimpleOption{
		Key: "secret-key",
	}

	auth := NewAuthorization(cfg, opts)

	bodyMap := map[string]string{
		"grant_type": "",
	}
	bodyBytes, _ := json.Marshal(bodyMap)

	ctx := newFakeContext(bodyBytes)

	err := auth.LoginOAuth(ctx)
	if err == nil {
		t.Fatal("esperado erro e não veio")
	}

	if ctx.Status != http.StatusBadRequest {
		t.Errorf("status esperado %d, got %d", http.StatusBadRequest, ctx.Status)
	}
}

//
// Teste hasRoleFromClaims
//

func TestHasRoleFromClaims_TrueQuandoTemRole(t *testing.T) {
	claims := jwt.MapClaims{
		"roles": []interface{}{"ADMIN", "USER"},
	}

	if !hasRoleFromClaims(claims, RolesPermissions("ADMIN")) {
		t.Fatal("ADMIN deveria existir")
	}
}

func TestHasRoleFromClaims_FalseQuandoNaoTemRole(t *testing.T) {
	claims := jwt.MapClaims{
		"roles": []interface{}{"USER"},
	}

	if hasRoleFromClaims(claims, RolesPermissions("ADMIN")) {
		t.Fatal("não deveria ter ADMIN")
	}
}
