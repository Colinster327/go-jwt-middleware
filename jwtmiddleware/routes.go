package jwtmiddleware

import (
	"reflect"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// LoginView handles user login and returns access and refresh tokens.
func LoginView(baseUserModel BaseUserModel, db *gorm.DB) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		type LoginRequest struct {
			Username string `json:"username" binding:"required" required:"This field is required"`
			Password string `json:"password" binding:"required" required:"This field is required"`
		}
		var request LoginRequest
		if err := ctx.ShouldBindJSON(&request); err != nil {
			ctx.JSON(400, gin.H{"error": err.Error()})
			return
		}

		userObj := reflect.New(getStructType(baseUserModel)).Interface()
		if err := db.Where("username = ?", request.Username).First(&userObj).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				ctx.JSON(404, gin.H{"detail": "User not found"})
				return
			} else {
				ctx.JSON(500, gin.H{"detail": "Database error"})
				return
			}
		}

		user, ok := userObj.(BaseUserModel)
		if !ok {
			ctx.JSON(500, gin.H{"detail": "User model does not implement BaseUserModel"})
			return
		}

		if !user.CheckPassword(request.Password) {
			ctx.JSON(401, gin.H{"detail": "Invalid credentials"})
			return
		}

		accessToken, refreshToken, err := refreshTokens(user.GetUsername())
		if err != nil {
			ctx.JSON(500, gin.H{"detail": err.Error()})
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
		type RefreshRequest struct {
			Refresh string `json:"refresh" binding:"required" required:"This field is required"`
		}

		var req RefreshRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(400, gin.H{"detail": err.Error()})
			return
		}

		username, err := validateRefreshToken(req.Refresh)
		if err != nil {
			ctx.JSON(401, gin.H{"detail": err.Error()})
			return
		}

		userObj := reflect.New(getStructType(baseUserModel)).Interface()
		if err := db.Where("username = ?", username).First(&userObj).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				ctx.JSON(404, gin.H{"detail": "User not found"})
				return
			} else {
				ctx.JSON(500, gin.H{"detail": "Database error"})
				return
			}
		}

		user, ok := userObj.(BaseUserModel)
		if !ok {
			ctx.JSON(500, gin.H{"detail": "User model does not implement BaseUserModel"})
			return
		}

		newAccess, newRefresh, err := refreshTokens(user.GetUsername())
		if err != nil {
			ctx.JSON(500, gin.H{"detail": err.Error()})
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
