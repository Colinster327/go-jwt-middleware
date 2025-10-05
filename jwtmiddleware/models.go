package jwtmiddleware

type BaseUserModel interface {
	GetUsername() string
	CheckPassword(password string) bool
	TableName() string
}
