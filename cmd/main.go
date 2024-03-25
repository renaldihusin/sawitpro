package main

import (
	"github.com/renaldihusin/sawitpro/handler"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.POST("/register", handler.RegistrationHandler)
	e.POST("/login", handler.LoginHandler)
	e.GET("/profile", handler.GetMyProfileHandler)
	e.PUT("/profile", handler.UpdateMyProfileHandler)

	e.Logger.Fatal(e.Start(":8080"))
}
