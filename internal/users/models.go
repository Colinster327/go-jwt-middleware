package users

import "time"

type User struct {
	Username  string    `gorm:"primaryKey;type:varchar(255)" json:"username" binding:"required"`
	Password  string    `json:"password" binding:"required"`
	Email     string    `json:"email" binding:"required,email"`
	Created   time.Time `gorm:"autoCreateTime" json:"created"`
	LastLogin time.Time `gorm:"autoUpdateTime" json:"last_login"`
}

func (u *User) GetUsername() string {
	return u.Username
}

func (u *User) CheckPassword(password string) bool {
	return u.Password == password
}

func (u *User) TableName() string {
	return "users"
}
