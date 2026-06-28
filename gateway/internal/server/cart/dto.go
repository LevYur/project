package cart

type AddToCartRequest struct {
	ProductID string `json:"product_id" binding:"required"`
	Quantity  int    `json:"quantity" binding:"required"`
}

type GetCartResponse struct {
	UserID     int        `json:"user_id" binding:"required"`
	Items      []CartItem `json:"items" binding:"required"`
	TotalPrice float64    `json:"total_price" binding:"required"`
}

type CartItem struct {
	ProductID string  `json:"product_id"`
	Name      string  `json:"name"`
	Price     float64 `json:"price"`
	Photo     string  `json:"main_photo"`
	Quantity  int     `json:"quantity"`
}
