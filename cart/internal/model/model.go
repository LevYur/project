package model

import "cartmodule/internal/errs"

type Cart struct {
	UserID     int        `json:"user_id"`
	Items      []CartItem `json:"items"`
	TotalPrice float64    `json:"total_price"`
}

type CartItem struct {
	ProductID string  `json:"product_id"` // store here
	Name      string  `json:"name"`       // get from products service
	Photo     string  `json:"main_photo"` // get from products service
	Price     float64 `json:"price"`      // get from products service
	Quantity  int     `json:"quantity"`   // store here
}

func (c *Cart) AddNewProductsIntoCart(productID string, quantity int) {

	found := false
	for i := range c.Items {

		if c.Items[i].ProductID == productID {
			c.Items[i].Quantity += quantity
			found = true
			break
		}
	}

	if !found {
		c.Items = append(c.Items, CartItem{ProductID: productID, Quantity: quantity})
	}
}

func (c *Cart) RemoveItem(productID string) error {

	for i := range c.Items {
		if c.Items[i].ProductID == productID {
			c.Items = append(c.Items[:i], c.Items[i+1:]...)
			return nil
		}
	}
	return errs.ErrNotFound
}

func (c *Cart) CalculateTotalPrice() {

	c.TotalPrice = 0

	for i := range c.Items {
		c.TotalPrice += c.Items[i].Price * float64(c.Items[i].Quantity)
	}
}
