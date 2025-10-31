package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/LevYur/project/auth/internal/server/users"
	"github.com/jmoiron/sqlx"
)

type Repo struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) *Repo {
	return &Repo{db: db}
}

func (r *Repo) IsEmailExists(ctx context.Context, email string) (bool, error) {

	const op = "auth.repository.users.IsEmailExists"

	var userID int

	err := r.db.GetContext(ctx, &userID, "SELECT user_id FROM auth_data WHERE email=$1", email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	return true, nil
}

func (r *Repo) BeginTx(ctx context.Context) (*sqlx.Tx, error) {

	const op = "auth.repository.users.BeginTx"

	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return tx, nil
}

func (r *Repo) CreateAuthDataTx(ctx context.Context, tx *sqlx.Tx, email, hashPass string) (
	userID int, err error) {

	const op = "auth.repository.users.CreateAuthData"

	err = tx.GetContext(ctx, &userID,
		"INSERT INTO auth_data (email, hash_pass) VALUES ($1, $2) RETURNING user_id",
		email, hashPass)

	if err != nil {
		return -1, fmt.Errorf("%s: %w", op, err)
	}

	return userID, nil
}

func (r *Repo) AddOutboxEventTx(ctx context.Context, tx *sqlx.Tx, eventType string, payload []byte) error {

	const op = "auth.repository.users.AddOutboxEvent"

	_, err := tx.ExecContext(ctx,
		"INSERT INTO outbox (event_type, payload) VALUES ($1, $2)",
		eventType, payload)

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *Repo) GetUnprocessedEvents(ctx context.Context) ([]users.OutboxEvent, error) {

	const op = "auth.repository.outbox.GetUnprocessedEvents"

	var events []users.OutboxEvent
	query := "SELECT id, event_type, payload " +
		"FROM outbox " +
		"WHERE processed=FALSE " +
		"ORDER BY created_at ASC " +
		"LIMIT 100"

	err := r.db.SelectContext(ctx, &events, query)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return events, nil
}

func (r *Repo) MarkEventProcessed(ctx context.Context, id int) error {

	const op = "auth.repository.outbox.MarkEventProcessed"

	query := "UPDATE outbox " +
		"SET processed=true, processed_at=NOW() " +
		"WHERE id=$1"

	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
