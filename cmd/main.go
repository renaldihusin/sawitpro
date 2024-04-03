package main

import (
	"net/http"
	"os"

	"github.com/renaldihusin/sawitpro/handler"
	"github.com/renaldihusin/sawitpro/repository"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Testing
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"hello": "world",
		})
	})

	e.POST("/register", handler.RegistrationHandler)
	e.POST("/login", handler.LoginHandler)
	e.GET("/profile", handler.GetMyProfileHandler)
	e.PUT("/profile", handler.UpdateMyProfileHandler)

	newServer()
	e.Logger.Fatal(e.Start(":8080"))
}

func newServer() *handler.Server {
	dbDsn := os.Getenv("DATABASE_URL")
	repo := repository.NewRepository(repository.NewRepositoryOptions{
		Dsn: dbDsn,
	})
	opts := handler.NewServerOptions{
		Repository: repo,
	}
	return handler.NewServer(opts)
}
