package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

var (
	privateKey = `-----BEGIN RSA PRIVATE KEY-----
	MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
	KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
	o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
	TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
	9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
	v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
	/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
	-----END RSA PRIVATE KEY-----`
)

func (ur *Repository) CreateUser(ctx context.Context, phone, fullName, password string) (string, error) {
	// Prepare SQL statement
	hashedPassword, err := hashPassword(password)
	if err != nil {
		log.Println("Failed to hash password: ", err)
		return "", err
	}

	stmt, err := ur.Db.Prepare("INSERT INTO users (phone_number, full_name, password) VALUES ($1, $2, $3) RETURNING id")
	if err != nil {
		log.Println("Failed to prepare SQL statement:", err)
		return "", err
	}
	defer stmt.Close()

	// Execute SQL statement
	var userID string
	err = stmt.QueryRow(phone, fullName, hashedPassword).Scan(&userID)
	if err != nil {
		log.Println("Failed to execute SQL statement:", err)
		return "", err
	}

	return userID, nil
}

func (ur *Repository) UpdateFullName(ctx context.Context, userID string, fullName string) error {
	stmt, err := ur.Db.Prepare("UPDATE users SET full_name = $1 WHERE user_id = $2")
	if err != nil {
		log.Println("Failed to prepare SQL statement:", err)
		return err
	}
	defer stmt.Close()

	// Execute the SQL statement with the provided parameters
	_, err = stmt.Exec(fullName, userID)
	if err != nil {
		// If an error occurs during the database update, return the error
		return err
	}

	// If the database update is successful, return nil (no error)
	return nil
}

func (ur *Repository) UpdatePhoneNumber(ctx context.Context, userID string, phoneNumber string) error {
	stmt, err := ur.Db.Prepare("UPDATE users SET phone_number = $1 WHERE user_id = $2")
	if err != nil {
		log.Println("Failed to prepare SQL statement:", err)
		return err
	}
	defer stmt.Close()

	// Execute the SQL statement with the provided parameters
	_, err = stmt.Exec(phoneNumber, userID)
	if err != nil {
		// If an error occurs during the database update, return the error
		return err
	}

	return nil
}

func (ur *Repository) CheckPhoneNumberExists(ctx context.Context, userID string, phoneNumber string) bool {
	var phone string
	err := ur.Db.QueryRow("SELECT phone WHERE phone_number = $1 AND user_id = $2", phoneNumber, userID).Scan(&phone)
	if err != nil {
		if err == sql.ErrNoRows {
			// User not found
			return false
		}
		log.Println("Failed to execute SQL query:", err)
		return false
	}

	if phone != "" {
		return true
	}

	return false
}

func (ur *Repository) AuthenticateUser(ctx context.Context, phone, password string) (string, string, error) {
	var userID, hashedPassword string

	// Query the database to find the user with the provided phone number
	hashedPassword, err := hashPassword(password)
	if err != nil {
		log.Println("Failed to hash password: ", err)
		return "", "", err
	}

	err = ur.Db.QueryRow("SELECT id, password FROM users WHERE phone = $1 AND password = $2", phone, hashedPassword).Scan(&userID, &hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			// User not found
			return "", "", err
		}
		log.Println("Failed to execute SQL query:", err)
		return "", "", err
	}

	// Compare the provided password with the hashed password from the database
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		// Passwords don't match
		return "", "", err
	}

	// Create JWT Token Signature for login user
	token, err := generateSignatureJWT(userID, hashedPassword, []byte(privateKey))
	if err != nil {
		log.Println("Failed generate signature JWT")
		return "", "", err
	}

	return userID, token, nil
}

func generateSignatureJWT(userID, password string, privateKey []byte) (string, error) {
	// Define the claims
	claims := jwt.MapClaims{
		"userID":   userID,
		"password": password,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expiration time (1 day)
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign the token with the private key
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func hashPassword(password string) (string, error) {
	// Generate a salted hash of the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Failed to generate salted hash:", err)
		return "", err
	}

	return string(hashedPassword), nil
}
