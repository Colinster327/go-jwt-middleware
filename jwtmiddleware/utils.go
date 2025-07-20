package jwtmiddleware

import (
	"os"
	"reflect"
	"time"

	"github.com/golang-jwt/jwt"
)

// getStructType retrieves the reflect.Type of the BaseUserModel.
func getStructType(baseUserModel BaseUserModel) reflect.Type {
	modelType := reflect.TypeOf(baseUserModel)

	if modelType.Kind() == reflect.Ptr {
		modelType = modelType.Elem()
	}

	return modelType
}

// validateAccessToken checks the validity of the access token and returns the username if valid.
func validateAccessToken(tokenString string) (string, error) {
	jwtAccessSecret := os.Getenv("JWT_ACCESS_SECRET")
	if jwtAccessSecret == "" {
		return "", jwt.NewValidationError("JWT_ACCESS_SECRET not set", jwt.ValidationErrorMalformed)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.NewValidationError("unexpected signing method", jwt.ValidationErrorSignatureInvalid)
		}
		return []byte(jwtAccessSecret), nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if refresh, ok := claims["refresh"].(bool); !ok || refresh {
			return "", jwt.NewValidationError("refresh token used as access token", jwt.ValidationErrorMalformed)
		}
		if exp, ok := claims["exp"].(float64); ok && time.Unix(int64(exp), 0).Before(time.Now()) {
			return "", jwt.NewValidationError("token expired", jwt.ValidationErrorExpired)
		}
		if username, ok := claims["username"].(string); ok {
			return username, nil
		}
	}

	return "", jwt.NewValidationError("invalid token", jwt.ValidationErrorMalformed)
}

// validateRefreshToken checks the validity of the refresh token and returns the username if valid.
func validateRefreshToken(tokenString string) (string, error) {
	jwtRefreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if jwtRefreshSecret == "" {
		return "", jwt.NewValidationError("JWT_REFRESH_SECRET not set", jwt.ValidationErrorMalformed)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.NewValidationError("unexpected signing method", jwt.ValidationErrorSignatureInvalid)
		}
		return []byte(jwtRefreshSecret), nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if refresh, ok := claims["refresh"].(bool); !ok || !refresh {
			return "", jwt.NewValidationError("access token used as refresh token", jwt.ValidationErrorMalformed)
		}
		if exp, ok := claims["exp"].(float64); ok && time.Unix(int64(exp), 0).Before(time.Now()) {
			return "", jwt.NewValidationError("token expired", jwt.ValidationErrorExpired)
		}
		if username, ok := claims["username"].(string); ok {
			return username, nil
		}
	}

	return "", jwt.NewValidationError("invalid token", jwt.ValidationErrorMalformed)
}

// generateAccessToken creates a new access token for the given username.
func generateAccessToken(username string) (string, error) {
	jwtAccessExpiration := os.Getenv("JWT_ACCESS_EXPIRATION")
	if jwtAccessExpiration == "" {
		jwtAccessExpiration = "15m"
	}

	accessExpiry, err := time.ParseDuration(jwtAccessExpiration)
	if err != nil {
		return "", jwt.NewValidationError("invalid JWT_ACCESS_EXPIRATION format", jwt.ValidationErrorMalformed)
	}

	jwtAccessSecret := os.Getenv("JWT_ACCESS_SECRET")
	if jwtAccessSecret == "" {
		return "", jwt.NewValidationError("JWT_ACCESS_SECRET not set", jwt.ValidationErrorMalformed)
	}

	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(accessExpiry).Unix(),
		"refresh":  false,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtAccessSecret))
}

// generateRefreshToken creates a new refresh token for the given username.
func generateRefreshToken(username string) (string, error) {
	jwtRefreshExpiration := os.Getenv("JWT_REFRESH_EXPIRATION")
	if jwtRefreshExpiration == "" {
		jwtRefreshExpiration = "24h"
	}

	refreshExpiry, err := time.ParseDuration(jwtRefreshExpiration)
	if err != nil {
		return "", jwt.NewValidationError("invalid JWT_REFRESH_EXPIRATION format", jwt.ValidationErrorMalformed)
	}

	jwtRefreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if jwtRefreshSecret == "" {
		return "", jwt.NewValidationError("JWT_REFRESH_SECRET not set", jwt.ValidationErrorMalformed)
	}

	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(refreshExpiry).Unix(),
		"refresh":  true,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtRefreshSecret))
}

// refreshTokens generates new access and refresh tokens for the given username.
func refreshTokens(username string) (string, string, error) {
	access, err := generateAccessToken(username)
	if err != nil {
		return "", "", err
	}

	refresh, err := generateRefreshToken(username)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}
