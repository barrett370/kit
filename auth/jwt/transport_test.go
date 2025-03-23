package jwt

import (
	"context"
	"net/http"
	"testing"
)

func TestHTTPToContext(t *testing.T) {
	reqFunc := HTTPToContext()

	// When the header doesn't exist
	ctx := reqFunc(context.Background(), &http.Request{})

	if ctx.Value(JWTContextKey) != nil {
		t.Error("Context shouldn't contain the encoded JWT")
	}

	// Authorization header value has invalid format
	header := http.Header{}
	header.Set("Authorization", "no expected auth header format value")
	ctx = reqFunc(context.Background(), &http.Request{Header: header})

	if ctx.Value(JWTContextKey) != nil {
		t.Error("Context shouldn't contain the encoded JWT")
	}

	// Authorization header is correct
	header.Set("Authorization", generateAuthHeaderFromToken(signedKey))
	ctx = reqFunc(context.Background(), &http.Request{Header: header})

	token := ctx.Value(JWTContextKey).(string)
	if token != signedKey {
		t.Errorf("Context doesn't contain the expected encoded token value; expected: %s, got: %s", signedKey, token)
	}
}

func TestContextToHTTP(t *testing.T) {
	reqFunc := ContextToHTTP()

	// No JWT is passed in the context
	ctx := context.Background()
	r := http.Request{}
	reqFunc(ctx, &r)

	token := r.Header.Get("Authorization")
	if token != "" {
		t.Error("authorization key should not exist in metadata")
	}

	// Correct JWT is passed in the context
	ctx = context.WithValue(context.Background(), JWTContextKey, signedKey)
	r = http.Request{Header: http.Header{}}
	reqFunc(ctx, &r)

	token = r.Header.Get("Authorization")
	expected := generateAuthHeaderFromToken(signedKey)

	if token != expected {
		t.Errorf("Authorization header does not contain the expected JWT; expected %s, got %s", expected, token)
	}
}
