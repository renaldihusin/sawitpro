package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestRegistrationHandler(t *testing.T) {
	tests := []struct {
		name          string
		reqBody       map[string]string
		expectedCode  int
		expectedError string
	}{
		{
			name: "InvalidPhoneNumber",
			reqBody: map[string]string{
				"phone":    "123",
				"fullName": "Testing",
				"password": "Password123!",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: `{"error":"Invalid phone number"}`,
		},
		{
			name: "InvalidFullName",
			reqBody: map[string]string{
				"phone":    "+62123456789",
				"fullName": "",
				"password": "Password123!",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: `{"error":"Full name must be between 3 and 60 characters"}`,
		},
		{
			name: "InvalidPassword",
			reqBody: map[string]string{
				"phone":    "+62123456789",
				"fullName": "Testing",
				"password": "",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: `{"error":"Password must be between 6 and 64 characters"}`,
		},
		{
			name: "InvalidPasswordFormatNoUpperCase",
			reqBody: map[string]string{
				"phone":    "+62123456789",
				"fullName": "Testing",
				"password": "password123!",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: `{"error":"Password must contain at least one uppercase letter, one number, and one special character"}`,
		},
		{
			name: "InvalidPasswordFormatNoNumber",
			reqBody: map[string]string{
				"phone":    "+62123456789",
				"fullName": "Testing",
				"password": "Password!",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: `{"error":"Password must contain at least one uppercase letter, one number, and one special character"}`,
		},
		{
			name: "InvalidPasswordFormatNoSpecialCharacter",
			reqBody: map[string]string{
				"phone":    "+62123456789",
				"fullName": "Testing",
				"password": "Password123",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: `{"error":"Password must contain at least one uppercase letter, one number, and one special character"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqJSON, _ := json.Marshal(tc.reqBody)
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(reqJSON))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			err := RegistrationHandler(c)

			if rec.Code != tc.expectedCode {
				t.Errorf("Expected status code %d, got %d", tc.expectedCode, rec.Code)
			}

			if strings.TrimSpace(rec.Body.String()) != tc.expectedError {
				t.Errorf("Expected response %s, got %s", tc.expectedError, rec.Body.String())
			}

			if err != nil && tc.expectedError == "" {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestLoginHandler(t *testing.T) {
	tests := []struct {
		name          string
		reqBody       map[string]string
		expectedCode  int
		expectedError string
	}{
		{
			name: "InvalidPhoneNumber",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: `{"error":"Invalid phone number"}`,
		},
		{
			name: "InvalidPassword",
			reqBody: map[string]string{
				"phone":    "+62123456789",
				"password": "",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: `{"error":"Password must be at least 6 characters long"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqJSON, _ := json.Marshal(tc.reqBody)
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(reqJSON))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			err := LoginHandler(c)
			if rec.Code != tc.expectedCode {
				t.Errorf("Expected status code %d, got %d", tc.expectedCode, rec.Code)
			}

			if strings.TrimSpace(rec.Body.String()) != tc.expectedError {
				t.Errorf("Expected response %s, got %s", tc.expectedError, rec.Body.String())
			}

			if err != nil && tc.expectedError == "" {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestGetMyProfileHandler(t *testing.T) {
	tests := []struct {
		name          string
		reqBody       map[string]string
		expectedCode  int
		expectedError string
	}{
		{
			name: "MissingHeaderAuthorization",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusForbidden,
			expectedError: `{"error":"Missing authorization token"}`,
		},
		{
			name: "FailedjwtParse",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusForbidden,
			expectedError: `{"error":"Failed to parse JWT token"}`,
		},
		{
			name: "InvalidToken",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusForbidden,
			expectedError: `{"error":"Invalid JWT token"}`,
		},
		{
			name: "InvalidJWTClaims",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusForbidden,
			expectedError: `{"error":"Invalid JWT claims"}`,
		},
		{
			name: "Success",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusOK,
			expectedError: `{"name":"name","phone":"phone"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqJSON, _ := json.Marshal(tc.reqBody)
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(reqJSON))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			if tc.name != "MissingHeaderAuthorization" {
				req.Header.Set("Authorization", "auth")
			}

			if tc.name == "FailedjwtParse" {
				jwtParse = func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
					return nil, assert.AnError
				}
			}

			if tc.name == "InvalidToken" {
				jwtParse = func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
					return &jwt.Token{
						Valid: false,
					}, nil
				}
			}

			if tc.name == "InvalidJWTClaims" {
				jwtParse = func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
					return &jwt.Token{
						Valid:  true,
						Claims: nil,
					}, nil
				}
			}

			if tc.name == "Success" {
				jwtParse = func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
					return &jwt.Token{
						Valid: true,
						Claims: jwt.MapClaims{
							"name":  "name",
							"phone": "phone",
						},
					}, nil
				}
			}

			err := GetMyProfileHandler(c)
			if rec.Code != tc.expectedCode {
				t.Errorf("Expected status code %d, got %d", tc.expectedCode, rec.Code)
			}

			if strings.TrimSpace(rec.Body.String()) != tc.expectedError {
				t.Errorf("Expected response %s, got %s", tc.expectedError, rec.Body.String())
			}

			if err != nil && tc.expectedError == "" {
				t.Errorf("Unexpected error: %v", err)
			}

			defer func() {
				jwtParse = jwt.Parse
			}()
		})
	}
}

func TestUpdateMyProfileHandler(t *testing.T) {
	tests := []struct {
		name          string
		reqBody       map[string]string
		expectedCode  int
		expectedError string
	}{
		{
			name: "MissingHeaderAuthorization",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusForbidden,
			expectedError: `{"error":"Missing authorization token"}`,
		},
		{
			name: "FailedjwtParse",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusForbidden,
			expectedError: `{"error":"Failed to parse JWT token"}`,
		},
		{
			name: "InvalidToken",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusForbidden,
			expectedError: `{"error":"Invalid JWT token"}`,
		},
		{
			name: "InvalidJWTClaims",
			reqBody: map[string]string{
				"phone":    "123",
				"password": "Password123!",
			},
			expectedCode:  http.StatusForbidden,
			expectedError: `{"error":"Invalid JWT claims"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqJSON, _ := json.Marshal(tc.reqBody)
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(reqJSON))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			if tc.name != "MissingHeaderAuthorization" {
				req.Header.Set("Authorization", "auth")
			}

			if tc.name == "FailedjwtParse" {
				jwtParse = func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
					return nil, assert.AnError
				}
			}

			if tc.name == "InvalidToken" {
				jwtParse = func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
					return &jwt.Token{
						Valid: false,
					}, nil
				}
			}

			if tc.name == "InvalidJWTClaims" {
				jwtParse = func(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
					return &jwt.Token{
						Valid:  true,
						Claims: nil,
					}, nil
				}
			}

			err := UpdateMyProfileHandler(c)
			if rec.Code != tc.expectedCode {
				t.Errorf("Expected status code %d, got %d", tc.expectedCode, rec.Code)
			}

			if strings.TrimSpace(rec.Body.String()) != tc.expectedError {
				t.Errorf("Expected response %s, got %s", tc.expectedError, rec.Body.String())
			}

			if err != nil && tc.expectedError == "" {
				t.Errorf("Unexpected error: %v", err)
			}

			defer func() {
				jwtParse = jwt.Parse
			}()
		})
	}
}
