package jwtmiddleware

import "github.com/golodash/galidator"

var (
	g                = galidator.G()
	loginValidator   = g.Validator(loginRequest{})
	refreshValidator = g.Validator(refreshRequest{})
)
