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
	Password    string `json:"password" binding:"required,min=8"`
	Phone       string `json:"phone" binding:"required,phone"`
	Name        string `json:"name" binding:"required,name,max=50"`
	Surname     string `json:"surname" binding:"omitempty,name,max=50"`
	FathersName string `json:"fathers_name" binding:"omitempty,name,max=50"`
	BirthDate   string `json:"birth_date" binding:"omitempty,birthdate"`
}

type RegisterResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       int    `json:"user_id"`
}
