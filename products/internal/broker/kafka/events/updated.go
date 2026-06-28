package events

import "time"

type EventType string

const (
	ProductUpdated EventType = "product.updated"
	ProductDeleted EventType = "product.deleted"
)

type ProductEvent struct {
	Type      EventType   `json:"type"`
	ProductID string      `json:"product_id"`
	Payload   interface{} `json:"payload"`
	Timestamp time.Time   `json:"timestamp"`
}

//type ProductPayload struct {
//	ID       string  `json:"id"`
//	Name     string  `json:"name"`
//	Price    float64 `json:"price"`
//	ImageURL string  `json:"image_url"`
//}
