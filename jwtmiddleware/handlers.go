package jwtmiddleware

type loginRequest struct {
	Username string `json:"username" binding:"required" required:"This field is required"`
	Password string `json:"password" binding:"required" required:"This field is required"`
}

type refreshRequest struct {
	Refresh string `json:"refresh" binding:"required" required:"This field is required"`
}
