package handler

import (
	"context"
	"net/http"
	"regexp"
	"strconv"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/renaldihusin/sawitpro/repository"
)

type UserRequest struct {
	Phone    string `json:"phone"`
	FullName string `json:"fullName"`
	Password string `json:"password"`
}

const (
	phonePattern = `^\+62\d{9,12}$`
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

	jwtParse = jwt.Parse
)

var repo repository.RepositoryInterface

// RegistrationHandler handles user registration
func RegistrationHandler(c echo.Context) error {
	var reqBody UserRequest
	if err := c.Bind(&reqBody); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Failed to parse request body"})
	}

	if !isValidPhone(reqBody.Phone) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid phone number"})
	}

	if len(reqBody.FullName) < 3 || len(reqBody.FullName) > 60 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Full name must be between 3 and 60 characters"})
	}

	if len(reqBody.Password) < 6 || len(reqBody.Password) > 64 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Password must be between 6 and 64 characters"})
	}

	if !containsUppercase(reqBody.Password) || !containsNumber(reqBody.Password) || !containsSpecialCharacter(reqBody.Password) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Password must contain at least one uppercase letter, one number, and one special character"})
	}

	_, err := repo.CreateUser(context.Background(), reqBody.Phone, reqBody.FullName, reqBody.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create user"})
	}

	response := map[string]string{"message": "User registered successfully"}
	return c.JSON(http.StatusOK, response)
}

// LoginHandler handles user login
func LoginHandler(c echo.Context) error {
	var reqBody UserRequest
	if err := c.Bind(&reqBody); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Failed to parse request body"})
	}

	if !isValidPhone(reqBody.Phone) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid phone number"})
	}

	if len(reqBody.Password) < 6 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Password must be at least 6 characters long"})
	}

	userID, jwtToken, err := repo.AuthenticateUser(context.Background(), reqBody.Phone, reqBody.Password)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid phone number or password"})
	}

	response := map[string]string{"message": "User logged in successfully", "userID": strconv.Itoa(int(userID)), "token": jwtToken}
	return c.JSON(http.StatusOK, response)
}

// GetMyProfileHandler handles requests to retrieve the user's profile
func GetMyProfileHandler(c echo.Context) error {
	tokenString := c.Request().Header.Get("Authorization")
	if tokenString == "" {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Missing authorization token"})
	}

	token, err := jwtParse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Failed to parse JWT token"})
	}

	if !token.Valid {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Invalid JWT token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Invalid JWT claims"})
	}

	name := claims["name"].(string)
	phone := claims["phone"].(string)
	return c.JSON(http.StatusOK, map[string]string{"name": name, "phone": phone})
}

// UpdateMyProfileHandler handles requests to update the user's profile
func UpdateMyProfileHandler(c echo.Context) error {
	tokenString := c.Request().Header.Get("Authorization")
	if tokenString == "" {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Missing authorization token"})
	}

	token, err := jwtParse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(privateKey), nil
	})
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Failed to parse JWT token"})
	}

	if !token.Valid {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Invalid JWT token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "Invalid JWT claims"})
	}

	var reqBody UserRequest
	if err := c.Bind(&reqBody); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Failed to parse request body"})
	}

	id := claims["id"].(int64)
	if reqBody.Phone != "" {
		if repo.CheckPhoneNumberExists(context.Background(), id, reqBody.Phone) {
			return c.JSON(http.StatusConflict, map[string]string{"error": "Phone number already exists"})
		}

		if err := repo.UpdatePhoneNumber(context.Background(), id, reqBody.Phone); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update phone number"})
		}
	}

	if reqBody.FullName != "" {
		if err := repo.UpdateFullName(context.Background(), id, reqBody.FullName); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update full name"})
		}
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Profile updated successfully"})
}

func containsUppercase(s string) bool {
	for _, c := range s {
		if 'A' <= c && c <= 'Z' {
			return true
		}
	}
	return false
}

func containsNumber(s string) bool {
	for _, c := range s {
		if '0' <= c && c <= '9' {
			return true
		}
	}
	return false
}

func containsSpecialCharacter(s string) bool {
	for _, c := range s {
		if !(('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')) {
			return true
		}
	}
	return false
}

func isValidPhone(phoneNumber string) bool {
	matched, err := regexp.MatchString(phonePattern, phoneNumber)
	if err != nil || !matched {
		return false
	}

	return true
}
