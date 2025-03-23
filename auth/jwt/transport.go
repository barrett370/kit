package jwt

import (
	"context"
	"fmt"
	stdhttp "net/http"
	"strings"

	"github.com/barrett370/kit/v2/transport/http"
)

const (
	bearer       string = "bearer"
	bearerFormat string = "Bearer %s"
)

// HTTPToContext moves a JWT from request header to context. Particularly
// useful for servers.
func HTTPToContext() http.RequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) context.Context {
		token, ok := extractTokenFromAuthHeader(r.Header.Get("Authorization"))
		if !ok {
			return ctx
		}

		return context.WithValue(ctx, JWTContextKey, token)
	}
}

// ContextToHTTP moves a JWT from context to request header. Particularly
// useful for clients.
func ContextToHTTP() http.RequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) context.Context {
		token, ok := ctx.Value(JWTContextKey).(string)
		if ok {
			r.Header.Add("Authorization", generateAuthHeaderFromToken(token))
		}
		return ctx
	}
}

func extractTokenFromAuthHeader(val string) (token string, ok bool) {
	authHeaderParts := strings.Split(val, " ")
	if len(authHeaderParts) != 2 || !strings.EqualFold(authHeaderParts[0], bearer) {
		return "", false
	}

	return authHeaderParts[1], true
}

func generateAuthHeaderFromToken(token string) string {
	return fmt.Sprintf(bearerFormat, token)
}
