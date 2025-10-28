package server

import (
	"auth/internal/server/auth"
	"auth/internal/server/users"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	httpSwagger "github.com/swaggo/http-swagger"
)

func AddAuthRoutes(router *gin.Engine, service auth.AuthService) *gin.Engine {

	router.GET("/api/auth/swagger/*any", gin.WrapH(httpSwagger.WrapHandler))
	router.GET("/api/auth/metrics", gin.WrapH(promhttp.Handler()))

	authGroup := router.Group("/auth")

	authHandler := auth.NewHandler(service)
	authGroup.POST("/login", authHandler.Login)
	authGroup.POST("/refresh", authHandler.Refresh)

	return router
}

func AddUsersRoutes(router *gin.Engine, service users.UsersService) *gin.Engine {

	authGroup := router.Group("/auth")

	usersHandler := users.NewHandler(service)
	authGroup.POST("/register", usersHandler.Register)

	return router
}
