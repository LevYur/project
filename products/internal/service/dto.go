package service

type Item struct {
	ProductID   string    `json:"product_id" binding:"required"`
	Article     string    `json:"article" binding:"required"`
	Name        string    `json:"name" binding:"required"`
	Description string    `json:"description" binding:"required"`
	Price       float64   `json:"price" binding:"required"`
	Warranty    int       `json:"warranty" binding:"required"`
	Media       ItemMedia `json:"media"`
}

type ItemMedia struct {
	MainPhoto string   `json:"main_photo" binding:"required"`
	AddPhoto  []string `json:"add_photo" binding:"required"`
}

type ItemPointer struct {
	Article     *string           `json:"article"`
	Name        *string           `json:"name"`
	Description *string           `json:"description"`
	Price       *float64          `json:"price"`
	Warranty    *int              `json:"warranty"`
	Media       *ItemMediaPointer `json:"media"`
}

type ItemMediaPointer struct {
	MainPhoto *string   `json:"main_photo"`
	AddPhoto  *[]string `json:"add_photo"`
}

func (i ItemPointer) IsEmpty() bool {
	return i.Article == nil && i.Name == nil && i.Price == nil && i.Description == nil && i.Warranty == nil && i.Media.MainPhoto == nil && i.Media.AddPhoto == nil
}
