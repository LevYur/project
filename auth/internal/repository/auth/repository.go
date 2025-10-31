package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	errs "github.com/LevYur/project/auth/internal/errors"
	"github.com/LevYur/project/auth/internal/server/auth"
	"github.com/jmoiron/sqlx"
)

type Repo struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *Repo {
	return &Repo{db: db}
}

func (r *Repo) GetByEmail(ctx context.Context, email string) (*auth.User, error) {

	const op = "auth.repository.GetByEmail"

	var user auth.User
	query := "SELECT user_id, email, hash_pass FROM auth_data WHERE email=$1"

	err := r.db.GetContext(ctx, &user, query, email)
	if err != nil {

		if errors.Is(err, sql.ErrNoRows) {
			return nil, errs.ErrUserNotFound
		}

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &user, nil
}
