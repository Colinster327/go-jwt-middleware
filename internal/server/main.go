package main

import (
	"log"
	"os"

	"github.com/Colinster327/go-jwt-middleware/internal/users"
	"github.com/Colinster327/go-jwt-middleware/jwtmiddleware"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Get the database connection string from environment variables
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		log.Fatalln("POSTGRES_DSN environment variable is not set")
	}

	// Initialize the database connection
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	// Auto-migrate the models
	if err := db.AutoMigrate(&users.User{}); err != nil {
		log.Fatalf("Failed to auto-migrate models: %v", err)
	}

	r := gin.Default()
	r.Use(func(ctx *gin.Context) {
		ctx.Set("db", db)
		ctx.Next()
	})

	// Routes for non-authenticated users
	r.POST("/login", jwtmiddleware.LoginView(&users.User{}, db))
	r.POST("/refresh", jwtmiddleware.RefreshTokenView(&users.User{}, db))

	// Middleware to check JWT token for authenticated routes
	r.Use(jwtmiddleware.JWTMiddleware(&users.User{}, db))

	// Routes for authenticated users
	r.GET("/users/current", users.UserView)

	r.Run(":8080")
}
