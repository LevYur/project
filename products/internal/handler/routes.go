package handler

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"productsmodule/internal/middleware"
	"time"
)

func SetupRoutes(service ServiceInterface, timeout time.Duration, log *zap.Logger) *gin.Engine {

	router := gin.New()

	router.Use(middleware.Recoverer(log))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(log))
	router.Use(middleware.Timeout(timeout))

	api := router.Group("/api")
	prodGroup := api.Group("/products")

	handler := New(service, log)

	prodGroup.POST("", handler.AddItems)
	prodGroup.PUT("/:product_id", handler.UpdateItemsPut)
	prodGroup.PATCH("/:product_id", handler.UpdateItemsPatch)
	prodGroup.DELETE("/:product_id", handler.DeleteItems)
	prodGroup.GET("/:product_id", handler.GetItems)
	prodGroup.GET("", handler.GetItems)
	prodGroup.POST("/batch", handler.GetItems)

	return router
}
