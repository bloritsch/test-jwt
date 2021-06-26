package main

import (
	"github.com/lestrrat-go/jwx/jwt"
	"time"
)

const (
	maxValidTime = 20 * time.Minute
)

func main() {

	token := jwt.New()
	_ = token.Set(jwt.IssuedAtKey, time.Now())
	_ = token.Set(jwt.ExpirationKey, time.Now().Add(10*time.Hour))

	err := jwt.Validate(token)
	if err != nil {
		panic(err)
	}

	// minimum requirement: must have expiration.  I.e. "forever" tokens not allowed
	_, exists := token.Get(jwt.ExpirationKey)
	if !exists {
		panic("expiration is required, forever tokens are not allowed")
	}

	_, exists = token.Get(jwt.IssuedAtKey)
	if !exists {
		panic("cannot calculate token valid time without issued at")
	}

	if token.Expiration().Sub(token.IssuedAt()) > maxValidTime {
		panic("someone attempted to fake a token outside of spec")
	}
}

/*
func alternativeValidation(token *jwt.Token) error {
	// The above should be the same as this
	return jwt.Validate(token,
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WitRequiredClaim(jwt.IssuedAtKey),
		jwt.WithMaxDelta(maxValidTime))
}
*/
