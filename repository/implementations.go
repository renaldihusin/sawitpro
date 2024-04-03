package repository

import (
	"context"
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

const (
	queryUpdatePhoneNumber = `UPDATE users SET phone_number = :phone_number WHERE id = :id`
	queryUpdateFullName    = `UPDATE users SET full_name = :full_name WHERE id = :id`
	queryInsert            = `INSERT INTO users (phone_number, full_name, password) VALUES (:phone_number, :full_name, :password) RETURNING id`
	querySelect            = `SELECT id, phone_number, full_name, password FROM users`
)

type User struct {
	ID       int64  `db:"id"`
	Phone    string `db:"phone_number"`
	Fullname string `db:"full_name"`
	Password string `db:"password"`
}

func (ur *Repository) CreateUser(ctx context.Context, phone, fullName, password string) (int64, error) {
	hashedPassword, err := hashPassword(password)
	if err != nil {
		log.Println("Failed to hash password: ", err)
		return 0, err
	}

	queryRowContext := ur.Db.QueryRowContext
	query, args, err := funcSQLXNamed(queryInsert, User{
		Phone:    phone,
		Fullname: fullName,
		Password: hashedPassword,
	})
	if err != nil {
		return 0, err
	}

	var userID int64
	err = queryRowContext(ctx, query, args...).Scan(&userID)
	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (ur *Repository) UpdateFullName(ctx context.Context, id int64, fullName string) error {
	execContext := ur.Db.ExecContext
	query, args, err := funcSQLXNamed(queryUpdateFullName, User{
		ID:       id,
		Fullname: fullName,
	})
	if err != nil {
		return err
	}

	_, err = execContext(ctx, query, args...)
	if err != nil {
		return err
	}

	return nil
}

func (ur *Repository) UpdatePhoneNumber(ctx context.Context, id int64, phoneNumber string) error {
	execContext := ur.Db.ExecContext
	query, args, err := funcSQLXNamed(queryUpdatePhoneNumber, User{
		ID:    id,
		Phone: phoneNumber,
	})
	if err != nil {
		return err
	}

	_, err = execContext(ctx, query, args...)
	if err != nil {
		return err
	}

	return nil
}

func (ur *Repository) CheckPhoneNumberExists(ctx context.Context, id int64, phoneNumber string) bool {
	queryRowContext := ur.Db.QueryRowContext
	query, args, err := funcSQLXNamed(querySelect+` WHERE id = :id AND phone_number = :phone_number`, User{
		ID:    id,
		Phone: phoneNumber,
	})
	if err != nil {
		return false
	}

	var user User
	err = queryRowContext(ctx, query, args...).Scan(&user.ID, &user.Phone, &user.Fullname, &user.Password)
	log.Print(err)
	if err != nil {
		return false
	}

	if user.ID > 0 {
		return true
	}

	return false
}

func (ur *Repository) AuthenticateUser(ctx context.Context, phone, password string) (int64, string, error) {
	hashedPassword, err := hashPassword(password)
	if err != nil {
		log.Println("Failed to hash password: ", err)
		return 0, "", err
	}

	queryRowContext := ur.Db.QueryRowContext
	query, args, err := funcSQLXNamed(querySelect+` WHERE phone_number = :phone_number AND password = :password`, User{
		Phone:    phone,
		Password: hashedPassword,
	})
	if err != nil {
		return 0, "", err
	}

	var user User
	err = queryRowContext(ctx, query, args...).Scan(&user.ID, &user.Password)
	log.Print(err)
	if err != nil {
		return 0, "", err
	}

	token, err := GenerateSignatureJWT(user.ID, hashedPassword, []byte(privateKey))
	if err != nil {
		log.Println("Failed generate signature JWT")
		return 0, "", err
	}

	return user.ID, token, nil
}

func GenerateSignatureJWT(userID int64, password string, privateKey []byte) (string, error) {
	claims := jwt.MapClaims{
		"userID":   userID,
		"password": password,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	}

	tokenJWT = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := tokenSignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := generatePassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Failed to generate salted hash:", err)
		return "", err
	}

	return string(hashedPassword), nil
}
