package service

type ItemForCart struct {
	ProductID string  `json:"product_id" binding:"required"`
	Name      string  `json:"name" binding:"required"`
	Photo     string  `json:"main_photo" binding:"required"`
	Price     float64 `json:"price" binding:"required"`
}
