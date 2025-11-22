package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

//
// Fakes / helpers
//

// fakeContext implementa HttpContext para testar o core sem Echo/Fiber
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

//
// Tests de GenerateToken
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

	if tokenStrPtr == nil || *tokenStrPtr == "" {
		t.Fatalf("token vazio ou nil")
	}

	tokenStr := *tokenStrPtr

	// Parse do token com a key HMAC
	parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// valida o método de assinatura
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("método de assinatura inesperado")
		}
		return []byte(opts.Key), nil
	})
	if err != nil {
		t.Fatalf("erro ao fazer parse do token: %v", err)
	}

	if !parsed.Valid {
		t.Fatalf("token não é válido")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims não é MapClaims")
	}

	if claims["subject"] != "user-123" {
		t.Errorf("subject errado, esperado 'user-123', got %#v", claims["subject"])
	}

	if claims["issuer"] != opts.Issuer {
		t.Errorf("issuer errado, esperado %s, got %#v", opts.Issuer, claims["issuer"])
	}

	if claims["foo"] != "bar" {
		t.Errorf("claim custom foo não encontrada/errada: %#v", claims["foo"])
	}
}

//
// Tests de LoginOAuth (password, client_credentials, erros)
//

func TestLoginOAuth_PasswordGrant_Sucesso(t *testing.T) {
	var receivedPass *OAuthPassword

	cfg := &OAuthConfigure{
		PasswordAuthorization: func(pass *OAuthPassword) AuthorizationRolesPassword {
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
		t.Fatalf("LoginOAuth retornou erro: %v", err)
	}

	if receivedPass == nil {
		t.Fatalf("PasswordAuthorization não foi chamado")
	}
	if receivedPass.Username != "john" || receivedPass.Password != "doe" {
		t.Errorf("dados de password incorretos: %#v", receivedPass)
	}

	if ctx.Status != http.StatusOK {
		t.Fatalf("status esperado %d, got %d", http.StatusOK, ctx.Status)
	}

	if ctx.JSONVal == nil {
		t.Fatalf("JSON de resposta está vazio")
	}
}

func TestLoginOAuth_ClientCredentials_Sucesso(t *testing.T) {
	var receivedClient *OAuthClient

	cfg := &OAuthConfigure{
		ClientCredentialsAuthorization: func(client *OAuthClient) AuthorizationRolesClient {
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
		t.Fatalf("LoginOAuth retornou erro: %v", err)
	}

	if receivedClient == nil {
		t.Fatalf("ClientCredentialsAuthorization não foi chamado")
	}

	if ctx.Status != http.StatusOK {
		t.Fatalf("status esperado %d, got %d", http.StatusOK, ctx.Status)
	}
}

func TestLoginOAuth_GrantTypeInvalido(t *testing.T) {
	cfg := &OAuthConfigure{}
	opts := &OAuthSimpleOption{
		Key:        "secret-key",
		AuthRouter: "/auth",
	}
	auth := NewAuthorization(cfg, opts)

	bodyMap := map[string]string{
		"grant_type": "invalid_type",
	}
	bodyBytes, _ := json.Marshal(bodyMap)

	ctx := newFakeContext(bodyBytes)

	err := auth.LoginOAuth(ctx)
	if err == nil {
		t.Fatalf("esperado erro para grant_type inválido")
	}

	if ctx.Status != http.StatusBadRequest {
		t.Fatalf("status esperado %d, got %d", http.StatusBadRequest, ctx.Status)
	}
}

func TestLoginOAuth_GrantTypeVazio(t *testing.T) {
	cfg := &OAuthConfigure{}
	opts := &OAuthSimpleOption{
		Key:        "secret-key",
		AuthRouter: "/auth",
	}
	auth := NewAuthorization(cfg, opts)

	bodyMap := map[string]string{
		"grant_type": "",
	}
	bodyBytes, _ := json.Marshal(bodyMap)

	ctx := newFakeContext(bodyBytes)

	err := auth.LoginOAuth(ctx)
	if err == nil {
		t.Fatalf("esperado erro para grant_type vazio")
	}

	if ctx.Status != http.StatusBadRequest {
		t.Fatalf("status esperado %d, got %d", http.StatusBadRequest, ctx.Status)
	}
}

//
// Tests de hasRoleFromClaims (se você criou essa função como combinamos)
//

func TestHasRoleFromClaims_TrueQuandoTemRole(t *testing.T) {
	claims := jwt.MapClaims{
		"roles": []interface{}{"ADMIN", "USER"},
	}

	if !hasRoleFromClaims(claims, RolesPermissions("ADMIN")) {
		t.Fatalf("esperado ter role ADMIN, mas retornou false")
	}
}

func TestHasRoleFromClaims_FalseQuandoNaoTemRole(t *testing.T) {
	claims := jwt.MapClaims{
		"roles": []interface{}{"USER"},
	}

	if hasRoleFromClaims(claims, RolesPermissions("ADMIN")) {
		t.Fatalf("não deveria ter role ADMIN, mas retornou true")
	}
}
