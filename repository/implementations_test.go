package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	gomock "github.com/golang/mock/gomock"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
)

func TestRepository_CreateUser(t *testing.T) {
	type mockFields struct {
		db sqlmock.Sqlmock
	}
	type args struct {
		ctx      context.Context
		phone    string
		fullname string
		password string
	}

	expectedQuery := `
	INSERT INTO users (phone_number, full_name, password) VALUES (?, ?, ?) RETURNING id
	`

	tests := []struct {
		name    string
		args    args
		mock    func(mock mockFields)
		want    int64
		wantErr error
	}{
		{
			name: "given_an_error_funcSQLXNamed_then_it_should_error",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				fullname: "name",
				password: "password",
			},
			mock: func(mock mockFields) {
				funcSQLXNamed = func(query string, arg interface{}) (string, []interface{}, error) {
					return "", nil, assert.AnError
				}
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "given_an_error_generatePassword_then_it_should_error",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				fullname: "name",
				password: "password",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return nil, assert.AnError
				}
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "given_an_error_when_QueryRowContext_then_it_should_error",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				fullname: "name",
				password: "password",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectQuery(expectedQuery).WithArgs(
					"123", "name", string([]byte{1}),
				).WillReturnError(assert.AnError)
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "success",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				fullname: "name",
				password: "password",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectQuery(expectedQuery).WithArgs(
					"123", "name", string([]byte{1}),
				).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(451)))
			},
			want:    451,
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockDB, dbMocker, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			mocks := mockFields{
				db: dbMocker,
			}
			repo := &Repository{
				Db: mockDB,
			}

			test.mock(mocks)
			defer func() {
				funcSQLXNamed = sqlx.Named
			}()

			runTest := func() {
				got, err := repo.CreateUser(test.args.ctx, test.args.phone, test.args.fullname, test.args.password)
				assert.Equal(t, test.want, got)
				assert.Equal(t, test.wantErr, err)
			}
			assert.NotPanics(t, runTest)
		})
	}
}

func TestRepository_UpdateFullName(t *testing.T) {
	type mockFields struct {
		db sqlmock.Sqlmock
	}
	type args struct {
		ctx      context.Context
		id       int64
		fullname string
	}

	expectedQuery := `
	UPDATE users SET full_name = ? WHERE id = ?
	`

	tests := []struct {
		name    string
		args    args
		mock    func(mock mockFields)
		want    int64
		wantErr error
	}{
		{
			name: "given_an_error_funcSQLXNamed_then_it_should_error",
			args: args{
				ctx:      context.Background(),
				id:       123,
				fullname: "name",
			},
			mock: func(mock mockFields) {
				funcSQLXNamed = func(query string, arg interface{}) (string, []interface{}, error) {
					return "", nil, assert.AnError
				}
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "given_an_error_when_QueryRowContext_then_it_should_error",
			args: args{
				ctx:      context.Background(),
				id:       123,
				fullname: "name",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectExec(expectedQuery).WithArgs(
					"name", 123,
				).WillReturnError(assert.AnError)
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "success",
			args: args{
				ctx:      context.Background(),
				id:       123,
				fullname: "name",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectExec(expectedQuery).WithArgs(
					"name", 123,
				).WillReturnResult(sqlmock.NewResult(123, 1)).
					WillReturnError(nil)
			},
			want:    451,
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockDB, dbMocker, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			mocks := mockFields{
				db: dbMocker,
			}
			repo := &Repository{
				Db: mockDB,
			}

			test.mock(mocks)
			defer func() {
				funcSQLXNamed = sqlx.Named
			}()

			runTest := func() {
				err := repo.UpdateFullName(test.args.ctx, test.args.id, test.args.fullname)
				assert.Equal(t, test.wantErr, err)
			}
			assert.NotPanics(t, runTest)
		})
	}
}

func TestRepository_UpdatePhoneNumber(t *testing.T) {
	type mockFields struct {
		db sqlmock.Sqlmock
	}
	type args struct {
		ctx         context.Context
		id          int64
		phonenumber string
	}

	expectedQuery := `
	UPDATE users SET phone_number = ? WHERE id = ?
	`

	tests := []struct {
		name    string
		args    args
		mock    func(mock mockFields)
		want    int64
		wantErr error
	}{
		{
			name: "given_an_error_funcSQLXNamed_then_it_should_error",
			args: args{
				ctx:         context.Background(),
				id:          123,
				phonenumber: "+628129318491",
			},
			mock: func(mock mockFields) {
				funcSQLXNamed = func(query string, arg interface{}) (string, []interface{}, error) {
					return "", nil, assert.AnError
				}
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "given_an_error_when_QueryRowContext_then_it_should_error",
			args: args{
				ctx:         context.Background(),
				id:          123,
				phonenumber: "+628129318491",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectExec(expectedQuery).WithArgs(
					"+628129318491", 123,
				).WillReturnError(assert.AnError)
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "success",
			args: args{
				ctx:         context.Background(),
				id:          123,
				phonenumber: "+628129318491",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectExec(expectedQuery).WithArgs(
					"+628129318491", 123,
				).WillReturnResult(sqlmock.NewResult(123, 1)).
					WillReturnError(nil)
			},
			want:    451,
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockDB, dbMocker, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			mocks := mockFields{
				db: dbMocker,
			}
			repo := &Repository{
				Db: mockDB,
			}

			test.mock(mocks)
			defer func() {
				funcSQLXNamed = sqlx.Named
			}()

			runTest := func() {
				err := repo.UpdatePhoneNumber(test.args.ctx, test.args.id, test.args.phonenumber)
				assert.Equal(t, test.wantErr, err)
			}
			assert.NotPanics(t, runTest)
		})
	}
}

func TestRepository_CheckPhoneNumberExists(t *testing.T) {
	type mockFields struct {
		db sqlmock.Sqlmock
	}
	type args struct {
		ctx   context.Context
		id    int64
		phone string
	}

	expectedQuery := `
	SELECT id, phone_number, full_name, password FROM users WHERE id = ? AND phone_number = ?
	`

	tests := []struct {
		name string
		args args
		mock func(mock mockFields)
		want bool
	}{
		{
			name: "given_an_error_funcSQLXNamed_then_it_should_error",
			args: args{
				ctx:   context.Background(),
				id:    123,
				phone: "123",
			},
			mock: func(mock mockFields) {
				funcSQLXNamed = func(query string, arg interface{}) (string, []interface{}, error) {
					return "", nil, assert.AnError
				}
			},
			want: false,
		},
		{
			name: "given_an_error_when_QueryRowContext_then_it_should_error",
			args: args{
				ctx:   context.Background(),
				id:    123,
				phone: "+6212353124",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectQuery(expectedQuery).WithArgs(
					123, "+6212353124",
				).WillReturnError(assert.AnError)
			},
			want: false,
		},
		{
			name: "emptyresult",
			args: args{
				ctx:   context.Background(),
				id:    123,
				phone: "+6212353124",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectQuery(expectedQuery).WithArgs(
					123, "+6212353124",
				).WillReturnRows(sqlmock.NewRows([]string{"id", "phone_number", "full_name", "password"}).AddRow(0, "", "", ""))
			},
			want: false,
		},
		{
			name: "success",
			args: args{
				ctx:   context.Background(),
				id:    123,
				phone: "+6212353124",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectQuery(expectedQuery).WithArgs(
					123, "+6212353124",
				).WillReturnRows(sqlmock.NewRows([]string{"id", "phone_number", "full_name", "password"}).AddRow(123, "123", "name", "password"))
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockDB, dbMocker, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			mocks := mockFields{
				db: dbMocker,
			}
			repo := &Repository{
				Db: mockDB,
			}

			test.mock(mocks)
			defer func() {
				funcSQLXNamed = sqlx.Named
			}()

			runTest := func() {
				got := repo.CheckPhoneNumberExists(test.args.ctx, test.args.id, test.args.phone)
				assert.Equal(t, test.want, got)
			}
			assert.NotPanics(t, runTest)
		})
	}
}

func TestRepository_AuthenticateUser(t *testing.T) {
	type mockFields struct {
		db sqlmock.Sqlmock
	}
	type args struct {
		ctx      context.Context
		phone    string
		password string
	}

	expectedQuery := querySelect + ` WHERE phone_number = ? AND password = ?`

	tests := []struct {
		name      string
		args      args
		mock      func(mock mockFields)
		want      int64
		wantToken string
		wantErr   error
	}{
		{
			name: "given_an_error_funcSQLXNamed_then_it_should_error",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				password: "password",
			},
			mock: func(mock mockFields) {
				funcSQLXNamed = func(query string, arg interface{}) (string, []interface{}, error) {
					return "", nil, assert.AnError
				}
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "given_an_error_generatePassword_then_it_should_error",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				password: "password",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return nil, assert.AnError
				}
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "given_an_error_when_QueryRowContext_then_it_should_error",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				password: "password",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectQuery(expectedQuery).WithArgs(
					"123", string([]byte{1}),
				).WillReturnError(assert.AnError)
			},
			want:    0,
			wantErr: assert.AnError,
		},
		{
			name: "errorGenerateSignature",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				password: "password",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectQuery(expectedQuery).WithArgs(
					"123", string([]byte{1}),
				).WillReturnRows(sqlmock.NewRows([]string{"id", "password"}).AddRow(int64(451), "password"))

				tokenSignedString = func(key interface{}) (string, error) {
					return "", assert.AnError
				}
			},
			want:      0,
			wantToken: "",
			wantErr:   assert.AnError,
		},
		{
			name: "success",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				password: "password",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectQuery(expectedQuery).WithArgs(
					"123", string([]byte{1}),
				).WillReturnRows(sqlmock.NewRows([]string{"id", "password"}).AddRow(int64(451), "password"))

				tokenSignedString = func(key interface{}) (string, error) {
					return "token", nil
				}
			},
			want:      451,
			wantToken: "token",
			wantErr:   nil,
		},
		{
			name: "success",
			args: args{
				ctx:      context.Background(),
				phone:    "123",
				password: "password",
			},
			mock: func(mock mockFields) {
				generatePassword = func(password []byte, cost int) ([]byte, error) {
					return []byte{1}, nil
				}
				mock.db.ExpectQuery(expectedQuery).WithArgs(
					"123", string([]byte{1}),
				).WillReturnRows(sqlmock.NewRows([]string{"id", "password"}).AddRow(int64(451), "password"))

				tokenSignedString = func(key interface{}) (string, error) {
					return "token", nil
				}
			},
			want:      451,
			wantToken: "token",
			wantErr:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockDB, dbMocker, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			mocks := mockFields{
				db: dbMocker,
			}
			repo := &Repository{
				Db: mockDB,
			}

			test.mock(mocks)
			defer func() {
				funcSQLXNamed = sqlx.Named
			}()

			runTest := func() {
				gotID, gotToken, err := repo.AuthenticateUser(test.args.ctx, test.args.phone, test.args.password)
				assert.Equal(t, test.want, gotID)
				assert.Equal(t, test.wantToken, gotToken)
				assert.Equal(t, test.wantErr, err)
			}
			assert.NotPanics(t, runTest)
		})
	}
}
