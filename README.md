# OAuth Middleware em Go (Echo + Fiber)

Este pacote fornece um **middleware de autenticação OAuth2 + JWT** reaproveitável para APIs em Go, com suporte a:

- Fluxo **password**
- Fluxo **client_credentials**
- Fluxo **refresh_token**
- Geração de **JWT** com `golang-jwt`
- Middlewares de validação para **Echo** e **Fiber**
- Verificação de **roles** dentro do token

A ideia é centralizar toda a lógica de autenticação/autorização em um único pacote (`oauth`), e apenas plugá-lo nas suas APIs.

---

## 📦 Dependências

No seu `go.mod`, você vai precisar de algo nessa linha:

```go
require (
    github.com/golang-jwt/jwt/v5 v5.2.0 // ou superior
    github.com/labstack/echo/v4 v4.12.0 // se usar Echo
    github.com/labstack/echo-jwt/v4 v4.3.0
    github.com/gofiber/fiber/v2 v2.52.0 // se usar Fiber
    github.com/gofiber/contrib/jwt v1.0.0
)
```

Ajuste as versões conforme o que já estiver usando no seu projeto.

---

## 🧱 Estrutura básica do pacote

Os principais tipos expostos pelo pacote:

```go
type OAuthSimpleOption struct {
    Key                     string   `json:"key"`
    Audience                []string `json:"audience"`
    ExpireTimeMinutes       int      `json:"expire_time_minutes"`
    ExpireTimeMinutesClient int      `json:"expire_time_minutes_client"`
    Issuer                  string   `json:"Issuer"`
    AuthRouter              string   `json:"auth_router"`
}

type OAuthConfigure struct {
    PasswordAuthorization                func(ctx RequestCtx, pass *OAuthPassword) AuthorizationRolesPassword
    ClientCredentialsAuthorization       func(ctx RequestCtx, client *OAuthClient) AuthorizationRolesClient
    RefreshTokenCredentialsAuthorization func(ctx RequestCtx, refresh *OAuthRefreshToken) AuthorizationRolesRefresh
    CustomActionRolesMiddleware          func(ctx RequestCtx token *jwt.Token, claims jwt.MapClaims) error
}

type RolesPermissions string
```

Criação da instância principal:

```go
auth := oauth.NewAuthorization(authConfigure, options)
```

Depois disso, você só pluga o `auth` no Echo ou no Fiber.

---

## 🔐 Fluxos suportados

A rota de autenticação (por padrão `/auth`) suporta os seguintes `grant_type` no corpo JSON:

### 1. Password

```json
{
  "grant_type": "password",
  "username": "user@example.com",
  "password": "minha_senha"
}
```

O pacote chamará:

```go
PasswordAuthorization(pass *OAuthPassword) AuthorizationRolesPassword
```

Você deve retornar:

- `Authorized` **true/false**
- `Roles` (lista de roles do usuário)
- `Subject` (id do usuário)
- `Claims` extras (opcional)
- `RefreshToken` (opcional)

### 2. Client Credentials

```json
{
  "grant_type": "client_credentials",
  "client_id": "my-service",
  "client_secret": "my-secret"
}
```

O pacote chamará:

```go
ClientCredentialsAuthorization(client *OAuthClient) AuthorizationRolesClient
```

### 3. Refresh Token

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "token_anterior"
}
```

O pacote chamará:

```go
RefreshTokenCredentialsAuthorization(refresh *OAuthRefreshToken) AuthorizationRolesRefresh
```

---

## 🧪 Estrutura de resposta de sucesso

Para `password` e `client_credentials`, o padrão de resposta usa essas structs:

```go
type AuthorizationBasic struct {
    Token_type   string `json:"token_type"`
    Expires_in   string `json:"expires_in"`
    Access_token string `json:"access_token"`
}

type AuthorizationRefreshPass struct {
    AuthorizationBasic
    Refresh_token string `json:"refresh_token"`
}
```

Exemplo de JSON:

```json
{
  "token_type": "Bearer",
  "expires_in": "2025-11-22 10:30:00",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "abc123..."
}
```

---

## 🧠 Geração de JWT

A função interna usada pelo pacote para gerar o token é:

```go
func (a *Authorization) GenerateToken(authBasic AuthorizationRolesBasic, expiresAt time.Time) (*string, error)
```

Claims padrão incluídos no JWT:

```go
claims := jwt.MapClaims{
    "roles":    authBasic.Roles,        // []string
    "subject":  authBasic.Subject,      // string (id do usuário/cliente)
    "audience": a.options.Audience,     // []string
    "issuer":   a.options.Issuer,       // string
    "exp":      jwt.NewNumericDate(expiresAt),
    "iat":      time.Now().Unix(),
}
```

Mais quaisquer claims extras que você passar em `AuthorizationRolesBasic.Claims`.

---

## 🚀 Usando com Echo

### 1. Configuração básica

```go
import (
    "net/http"

    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"

    "seu-modulo/oauth"
)

func customActionRolesMiddleware(token *jwt.Token, claims jwt.MapClaims) error {
    // Ex.: logar, checar algo específico no token, etc.
    return nil
}

func main() {
    options := &oauth.OAuthSimpleOption{
        Key:                     "minha-chave-secreta",
        ExpireTimeMinutes:       30,
        ExpireTimeMinutesClient: 60,
        Audience:                []string{"minha-api"},
        Issuer:                  "meu-sistema",
        AuthRouter:              "/auth",
    }

    authConfigure := &oauth.OAuthConfigure{
        ClientCredentialsAuthorization:       myAuthService.ClientCredentialsAuthorization,
        PasswordAuthorization:                myAuthService.PasswordAuthorization,
        RefreshTokenCredentialsAuthorization: myAuthService.RefreshTokenCredentialsAuthorization,
        CustomActionRolesMiddleware:          customActionRolesMiddleware,
    }

    e := echo.New()

    e.Use(middleware.CORS())

    auth := oauth.NewAuthorization(authConfigure, options)

    // Rota de autenticação (POST /auth)
    auth.CreateAuthRouter(e)

    // Endpoint público
    e.GET("/health", func(c echo.Context) error {
        return c.String(http.StatusOK, "Health check passed")
    })

    // Middleware JWT padrão
    jwtValidate := auth.GetDefaultMiddleWareJwtValidate()

    // Grupo protegido apenas com JWT válido
    g := e.Group("/api", jwtValidate)

    g.GET("/me", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]string{"msg": "rota autenticada"})
    })

    // Exemplo de rota que exige role específica
    g.GET("/admin", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]string{"msg": "rota admin"})
    }, auth.RolesMiddleware(oauth.RolesPermissions("ADMIN")))

    e.Logger.Fatal(e.Start(":8080"))
}
```

### 2. Implementando o serviço de autenticação

Exemplo simplificado:

```go
type AuthService struct{}

func (s *AuthService) PasswordAuthorization(pass *oauth.OAuthPassword) oauth.AuthorizationRolesPassword {
    // Aqui você valida username/senha num banco, etc.
    if pass.Username == "admin" && pass.Password == "123" {
        return oauth.AuthorizationRolesPassword{
            AuthorizationRolesBasic: oauth.AuthorizationRolesBasic{
                Authorized: true,
                Roles:      []string{"ADMIN"},
                Subject:    "user-1",
                Claims: map[string]string{
                    "email": "admin@example.com",
                },
            },
            RefreshToken: "refresh-xyz",
        }
    }

    return oauth.AuthorizationRolesPassword{
        AuthorizationRolesBasic: oauth.AuthorizationRolesBasic{
            Authorized: false,
        },
    }
}
```

Você encaixa esse serviço em `OAuthConfigure`.

---

## 🚀 Usando com Fiber

### 1. Configuração básica

```go
import (
    "github.com/gofiber/fiber/v2"

    "seu-modulo/oauth"
)

func customActionRolesMiddleware(token *jwt.Token, claims jwt.MapClaims) error {
    // Checagens extras, se necessário
    return nil
}

func main() {
    options := &oauth.OAuthSimpleOption{
        Key:                     "minha-chave-secreta",
        ExpireTimeMinutes:       30,
        ExpireTimeMinutesClient: 60,
        Audience:                []string{"minha-api"},
        Issuer:                  "meu-sistema",
        AuthRouter:              "/auth",
    }

    authConfigure := &oauth.OAuthConfigure{
        ClientCredentialsAuthorization:       myAuthService.ClientCredentialsAuthorization,
        PasswordAuthorization:                myAuthService.PasswordAuthorization,
        RefreshTokenCredentialsAuthorization: myAuthService.RefreshTokenCredentialsAuthorization,
        CustomActionRolesMiddleware:          customActionRolesMiddleware,
    }

    app := fiber.New()

    auth := oauth.NewAuthorization(authConfigure, options)

    // Rota de autenticação: POST /auth
    app.Post(options.AuthRouter, auth.FiberHandler())

    // Middleware JWT para Fiber
    jwtValidate := auth.GetFiberDefaultMiddleWareJwtValidate()

    app.Get("/health", func(c *fiber.Ctx) error {
        return c.SendString("Health check passed")
    })

    // Rotas protegidas
    api := app.Group("/api", jwtValidate)

    api.Get("/me", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"msg": "rota autenticada"})
    })

    // Exemplo com roles
    api.Get("/admin",
        func(c *fiber.Ctx) error {
            return c.JSON(fiber.Map{"msg": "rota admin"})
        },
        auth.FiberRolesMiddleware(oauth.RolesPermissions("ADMIN")),
    )

    app.Listen(":8080")
}
```

---

## 🔍 Como funciona a validação de roles

Internamente, o token deve ter um claim `roles` contendo uma lista de strings, por exemplo:

```json
{
  "roles": ["ADMIN", "USER"]
}
```

A função helper usada para verificar isso (compartilhada entre Echo e Fiber):

```go
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
```

### Echo

No `RolesMiddleware`, o token vem do `c.Get("user")`:

```go
user := c.Get("user").(*jwt.Token)
claims := user.Claims.(jwt.MapClaims)

if !hasRoleFromClaims(claims, roleList...) {
    return echo.ErrForbidden
}
```

### Fiber

No `FiberRolesMiddleware`, o token vem de `c.Locals("user")`:

```go
userToken := c.Locals("user").(*jwt.Token)
claims := userToken.Claims.(jwt.MapClaims)

if !hasRoleFromClaims(claims, roleList...) {
    return fiber.ErrForbidden
}
```

---

## ✅ Resumo

- Você configura o pacote com:
  - `OAuthSimpleOption` (chave, issuer, audience, expiração, rota `/auth`)
  - `OAuthConfigure` (funções que **sabem autenticar** de verdade: senha, client credentials, refresh)
- O pacote:
  - Lê o `grant_type` do corpo JSON
  - Chama a função apropriada do seu código
  - Gera um JWT com roles, subject, issuer, audience, exp, iat
  - Responde com `access_token` (+ opcional `refresh_token`)
- Depois:
  - Você usa `GetDefaultMiddleWareJwtValidate` (Echo) ou `GetFiberDefaultMiddleWareJwtValidate` (Fiber)
  - Protege rotas com JWT e, se quiser, com roles (`RolesMiddleware` / `FiberRolesMiddleware`)

Com isso, sua lógica de autenticação/autorização fica centralizada, testável e pronta pra reutilizar em múltiplas APIs. 🚀
