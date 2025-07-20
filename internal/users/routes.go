package users

import "github.com/gin-gonic/gin"

func UserView(ctx *gin.Context) {
	user := ctx.MustGet("user").(*User)

	ctx.JSON(200, gin.H{
		"username": user.Username,
		"email":    user.Email,
	})
}
