package oauth

import "context"

type HttpContext interface {
	Body() ([]byte, error)
	JSON(code int, i interface{}) error
	String(code int, s string) error

	RequestContext() context.Context
	Header(key string) string

	Set(key string, val interface{})
	Get(key string) interface{}
}

type RequestCtx = HttpContext
