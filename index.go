package handler

import (
	
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v4"
)

// MongoDB client and collections
var client *mongo.Client
var usersCollection *mongo.Collection

// JWT secret
var jwtSecret = []byte("abdullah55")

// MongoDB connection string from environment
var mongoURI = os.Getenv("MONGO_URI")

// Initialize MongoDB connection
func initMongo() {
	if mongoURI == "" {
		log.Fatal("MONGO_URI environment variable not set")
	}

	var err error
	client, err = mongo.Connect(nil, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}

	usersCollection = client.Database("userdb").Collection("users")
}

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
	// Initialize MongoDB connection
	initMongo()

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

		// Save the user data to MongoDB
		_, err = usersCollection.InsertOne(nil, bson.M{
			"username":    req.Username,
			"email":       req.Email,
			"age":         req.Age,
			"company_name": req.CompanyName,
			"password":    hashedPassword,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Error saving user"})
			return
		}

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

		// Fetch the user by email from MongoDB
		var user struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		err := usersCollection.FindOne(nil, bson.M{"email": req.Email}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
			return
		}

		// Check if the provided password matches the stored hashed password
		if !CheckPasswordHash(req.Password, user.Password) {
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
