// This file contains the interfaces for the repository layer.
// The repository layer is responsible for interacting with the database.
// For testing purpose we will generate mock implementations of these
// interfaces using mockgen. See the Makefile for more information.
package repository

import "context"

type RepositoryInterface interface {
	CreateUser(ctx context.Context, phone, fullName, password string) (int64, error)
	UpdateFullName(ctx context.Context, userID int64, fullName string) error
	UpdatePhoneNumber(ctx context.Context, userID int64, phoneNumber string) error
	CheckPhoneNumberExists(ctx context.Context, userID int64, phoneNumber string) bool
	AuthenticateUser(ctx context.Context, phone string, password string) (int64, string, error)
}
