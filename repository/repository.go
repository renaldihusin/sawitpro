// This file contains the repository implementation layer.
package repository

import (
	"database/sql"

	"github.com/golang-jwt/jwt"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

//go:generate mockgen -source=./repository.go -destination=./repository_mock.go -package=repository

// For mocking purpose
var (
	tokenJWT          *jwt.Token
	tokenSignedString = tokenJWT.SignedString
	generatePassword  = bcrypt.GenerateFromPassword
	funcSQLXNamed     = sqlx.Named
)

type Repository struct {
	Db *sql.DB
}

type NewRepositoryOptions struct {
	Dsn string
}

func NewRepository(opts NewRepositoryOptions) *Repository {
	db, err := sql.Open("postgres", opts.Dsn)
	if err != nil {
		panic(err)
	}
	return &Repository{
		Db: db,
	}
}
