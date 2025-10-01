package auth

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       int    `json:"user_id"`
}

type RegisterRequest struct {
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required"`
	Phone       string `json:"phone" binding:"required"`
	Name        string `json:"name" binding:"omitempty"`
	Surname     string `json:"surname" binding:"omitempty"`
	FathersName string `json:"fathers_name" binding:"omitempty"`
	BirthDate   string `json:"birth_date" binding:"omitempty"`
}

type RegisterResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       int    `json:"user_id"`
}
