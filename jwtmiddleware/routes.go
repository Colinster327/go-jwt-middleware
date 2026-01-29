package jwtmiddleware

import (
	"reflect"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// LoginView handles user login and returns access and refresh tokens.
func LoginView(baseUserModel BaseUserModel, db *gorm.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var request loginRequest
		if err := ctx.BindJSON(&request); err != nil {
			ctx.JSON(400, gin.H{"error": loginValidator.DecryptErrors(err)})
			return
		}

		userObj := reflect.New(getStructType(baseUserModel)).Interface()
		if err := db.Where("username = ?", request.Username).First(&userObj).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				ctx.JSON(404, gin.H{"error": "Invalid credentials"})
				return
			} else {
				ctx.JSON(500, gin.H{"error": "Database error"})
				return
			}
		}

		user, ok := userObj.(BaseUserModel)
		if !ok {
			ctx.JSON(500, gin.H{"error": "User model does not implement BaseUserModel"})
			return
		}

		if !user.CheckPassword(request.Password) {
			ctx.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		accessToken, refreshToken, err := refreshTokens(user.GetUsername())
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(200, gin.H{
			"access":  accessToken,
			"refresh": refreshToken,
		})
	}
}

// RefreshTokenView handles the refresh token request and returns new access and refresh tokens.
func RefreshTokenView(baseUserModel BaseUserModel, db *gorm.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req refreshRequest
		if err := ctx.BindJSON(&req); err != nil {
			ctx.JSON(400, gin.H{"error": refreshValidator.DecryptErrors(err)})
			return
		}

		username, err := validateRefreshToken(req.Refresh)
		if err != nil {
			ctx.JSON(401, gin.H{"error": err.Error()})
			return
		}

		userObj := reflect.New(getStructType(baseUserModel)).Interface()
		if err := db.Where("username = ?", username).First(&userObj).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				ctx.JSON(404, gin.H{"error": "User not found"})
				return
			} else {
				ctx.JSON(500, gin.H{"error": "Database error"})
				return
			}
		}

		user, ok := userObj.(BaseUserModel)
		if !ok {
			ctx.JSON(500, gin.H{"error": "User model does not implement BaseUserModel"})
			return
		}

		newAccess, newRefresh, err := refreshTokens(user.GetUsername())
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(200, gin.H{
			"access":  newAccess,
			"refresh": newRefresh,
		})
	}
}

// CreateTokens generates new access and refresh tokens for a given username.
func CreateTokens(username string) (string, string, error) {
	return refreshTokens(username)
}

// ValidateAccessToken validates an access token and returns the username if valid.
func ValidateToken(tokenString string) (string, error) {
	return validateAccessToken(tokenString)
}
