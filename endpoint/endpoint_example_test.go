package endpoint_test

import (
	"context"
	"fmt"

	"github.com/barrett370/kit/v2/endpoint"
)

func ExampleChain() {
	e := endpoint.Chain(
		annotate("first"),
		annotate("second"),
		annotate("third"),
	)(myEndpoint)

	if _, err := e(ctx, req); err != nil {
		panic(err)
	}

	// Output:
	// first pre
	// second pre
	// third pre
	// my endpoint!
	// third post
	// second post
	// first post
}

var (
	ctx = context.Background()
	req = struct{}{}
)

func annotate(s string) endpoint.Middleware[any, any] {
	return func(next endpoint.Endpoint[any, any]) endpoint.Endpoint[any, any] {
		return func(ctx context.Context, request interface{}) (interface{}, error) {
			fmt.Println(s, "pre")
			defer fmt.Println(s, "post")
			return next(ctx, request)
		}
	}
}

func myEndpoint(context.Context, interface{}) (interface{}, error) {
	fmt.Println("my endpoint!")
	return struct{}{}, nil
}
