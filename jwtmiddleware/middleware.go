package jwtmiddleware

import (
	"reflect"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// JWTMiddleware is a Gin middleware that validates JWT access tokens and retrieves the user from the database.
func JWTMiddleware(baseUserModel BaseUserModel, db *gorm.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.AbortWithStatusJSON(401, gin.H{"detail": "Authorization header required"})
			return
		}

		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			ctx.AbortWithStatusJSON(401, gin.H{"detail": "Invalid Authorization header format"})
			return
		}

		stringToken := authHeader[len("Bearer "):]
		username, err := validateAccessToken(stringToken)
		if err != nil {
			ctx.AbortWithStatusJSON(401, gin.H{"detail": err.Error()})
			return
		}

		userObj := reflect.New(getStructType(baseUserModel)).Interface()
		if err := db.Where("username = ?", username).First(userObj).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				ctx.AbortWithStatusJSON(401, gin.H{"detail": "User not found"})
				return
			} else {
				ctx.AbortWithStatusJSON(500, gin.H{"detail": "Database error"})
				return
			}
		}

		user, ok := userObj.(BaseUserModel)
		if !ok {
			ctx.AbortWithStatusJSON(500, gin.H{"detail": "Invalid user model type"})
			return
		}

		ctx.Set("user", user)
		ctx.Next()
	}
}
