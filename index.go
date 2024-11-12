package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
)

// Secret key for JWT
var jwtSecret = []byte("abdullah55")

// HashPassword hashes a plain password
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashedPassword), err
}

// CheckPasswordHash compares plain password with hashed password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateJWT generates a new JWT token
func GenerateJWT(userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	return token.SignedString(jwtSecret)
}

// Handler function for Vercel
func Handler(w http.ResponseWriter, r *http.Request) {
	router := gin.Default()

	// Signup route
	router.POST("/signup", func(c *gin.Context) {
		var req struct {
			Username    string `json:"username"`
			Email       string `json:"email"`
			Age         int    `json:"age"`
			Password    string `json:"password"`
			CompanyName string `json:"company_name"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request"})
			return
		}

		// Hash the password
		hashedPassword, err := HashPassword(req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Error hashing password"})
			return
		}

		// Simulate saving user data to a database
		// Example: db.SaveUser(req.Username, req.Email, req.Age, req.CompanyName, hashedPassword)

		// Return response with user details and hashed password
		c.JSON(http.StatusOK, gin.H{
			"message":      "User registered successfully",
			"username":     req.Username,
			"email":        req.Email,
			"age":          req.Age,
			"company_name": req.CompanyName,
			"hashed_password": hashedPassword, // Now we use hashedPassword
		})
	})

	// Login route
	router.POST("/login", func(c *gin.Context) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request"})
			return
		}

		// Simulate fetching the hashed password from the database by email
		// In reality, you should query your DB and fetch the hashed password
		// Example: db.GetHashedPasswordByEmail(req.Email)
		hashedPasswordFromDB := "$2a$12$dummyhashedpassword"

		// Check if the provided password matches the stored hashed password
		if !CheckPasswordHash(req.Password, hashedPasswordFromDB) {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
			return
		}

		// Generate JWT token after successful login
		token, err := GenerateJWT("user_id_placeholder")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Error generating token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	// Serve the Gin router as the response to the Vercel function
	router.ServeHTTP(w, r)
}
