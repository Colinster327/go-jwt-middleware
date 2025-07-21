# go-jwt-middleware

`go-jwt-middleware` is a Go package that provides JWT authentication middleware for the Gin web framework. It simplifies the process of validating JWT access tokens and retrieving user information from a database.

## Features

- Middleware for validating JWT access tokens.
- User retrieval from a database using GORM.
- Support for environment-based configuration of JWT secrets and expiration times.
- Helper functions for creating and refreshing tokens.

## Installation

```bash
go get github.com/Colinster327/go-jwt-middleware
```

## Environment Variables

Before using the package, ensure the following environment variables are set:

- `JWT_ACCESS_SECRET`: Secret key for signing access tokens.
- `JWT_REFRESH_SECRET`: Secret key for signing refresh tokens.
- `JWT_ACCESS_EXPIRATION`: Expiration time for access tokens (ex: 60m).
- `JWT_REFRESH_EXPIRATION`: Expiration time for refresh tokens (ex: 24h).

## Usage

### Middleware Setup

```go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/Colinster327/go-jwt-middleware/jwtmiddleware"
	"gorm.io/gorm"
)

func main() {
	r := gin.Default()
	db := setupDatabase() // Replace with your database setup

	// Define routes
    // IMPORTANT: Ensure these routes and any other ones that don't require
    // authorization are defined BEFORE applying the middleware
	r.POST("/login", LoginView(&CustomUserModel{}, db))
	r.POST("/refresh", RefreshTokenView(&CustomUserModel{}, db))

	// Apply JWT middleware
	r.Use(JWTMiddleware(&CustomUserModel{}, db))


	r.Run(":8080")

    ...

    // If you just need to create tokens without validation, you can use this function
    username := "testuser123"
    access, refresh, err := CreateTokens(username)
}
```

Once the middleware is set up, it will automatically validate JWT tokens for protected routes. If the token is valid, the user information will be available in the context under the `user` field, otherwise it will return a 401.

```go
func ProtectedRoute(ctx *gin.Context) {
    // Make sure to type assert the user from the context
    user := ctx.MustGet("user").(*CustomUserModel)

    c.JSON(200, gin.H{"message": "Welcome!", "user": user.Username})
}
```

## License

This package is licensed under the MIT License. See the LICENSE file for details.
