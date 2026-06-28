package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"productsmodule/internal/constants"
	"productsmodule/internal/errs"
	"productsmodule/internal/service"
	"strings"
	"time"
)

type Repo struct {
	DB       *sql.DB
	RDB      *redis.Client
	RedisTTL time.Duration
	log      *zap.Logger
}

func New(db *sql.DB, rdb *redis.Client, ttl time.Duration, log *zap.Logger) *Repo {
	return &Repo{DB: db, RDB: rdb, RedisTTL: ttl, log: log}
}

func (r *Repo) SaveToRedis(ctx context.Context, items []service.Item) error {

	var firstErr error

	for _, i := range items {
		key := "products_db:" + i.ProductID

		jsonItem, err := json.Marshal(i)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("marshal error: %w", err)
			}
			continue
		}

		err = r.RDB.Set(ctx, key, jsonItem, r.RedisTTL).Err()
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("redis set error: %w", err)
		}
	}

	return firstErr
}

func (r *Repo) SaveToDB(ctx context.Context, items []service.Item) error {

	const op = "products.repo.SaveToDB"

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: ❌ begin tx failed: %w", op, err)
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			_ = tx.Commit()
		}
	}()

	for _, i := range items {

		query1 := `INSERT INTO main 
    	(product_id, article, name, description, price, warranty, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW());`

		_, err := tx.ExecContext(ctx, query1,
			i.ProductID, i.Article, i.Name, i.Description, i.Price, i.Warranty)
		if err != nil {
			return fmt.Errorf("%s: insert main table error: %w", op, err)
		}

		query2 := `INSERT INTO media (product_id, main_photo, add_photo, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW());`

		_, err = tx.ExecContext(ctx, query2, i.ProductID, i.Media.MainPhoto, i.Media.AddPhoto)
		if err != nil {
			return fmt.Errorf("%s: insert media table error: %w", op, err)
		}
	}

	return nil
}

func (r *Repo) UpdateInRedis(ctx context.Context, item service.Item) error {

	key := "products_db:" + item.ProductID

	jsonItem, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	err = r.RDB.Set(ctx, key, jsonItem, r.RedisTTL).Err()
	if err != nil {
		return fmt.Errorf("redis set error: %w", err)
	}

	return nil
}

func (r *Repo) UpdateInDBPut(ctx context.Context, item service.Item) error {

	const op = "products.repo.UpdateInDBPut"

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: ❌ begin tx failed: %w", op, err)
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			_ = tx.Commit()
		}
	}()

	query1 := `UPDATE main 
	SET article=$1, name=$2, description=$3, price=$4, warranty=$5, updated_at=NOW() 
	WHERE product_id=$6;`

	res1, err := tx.ExecContext(ctx, query1,
		item.Article, item.Name, item.Description, item.Price, item.Warranty, item.ProductID)
	if err != nil {
		return fmt.Errorf("%s: update main table error: %w", op, err)
	}

	row, _ := res1.RowsAffected()
	if row == 0 {
		return fmt.Errorf("%s main table: %v", op, errs.ErrNotFound)
	}

	query2 := `UPDATE media SET main_photo=$1, add_photo=$2, updated_at=NOW() WHERE product_id = $3;`

	res2, err := tx.ExecContext(ctx, query2, item.Media.MainPhoto, item.Media.AddPhoto, item.ProductID)
	if err != nil {
		return fmt.Errorf("%s: update media table error: %w", op, err)
	}

	row, _ = res2.RowsAffected()
	if row == 0 {
		return fmt.Errorf("%s media table: %v", op, errs.ErrNotFound)
	}

	return nil
}

func (r *Repo) UpdateInDBPatch(ctx context.Context, productID string, item service.ItemPointer) error {

	const op = "products.repo.UpdateInDBPatch"

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: begin tx: %w", op, err)
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			_ = tx.Commit()
		}
	}()

	var (
		setParts []string
		args     []any
		argIdx   = 1
	)

	if item.Article != nil {
		setParts = append(setParts, fmt.Sprintf("article = $%d", argIdx))
		args = append(args, *item.Article)
		argIdx++
	}
	if item.Name != nil {
		setParts = append(setParts, fmt.Sprintf("name = $%d", argIdx))
		args = append(args, *item.Name)
		argIdx++
	}
	if item.Description != nil {
		setParts = append(setParts, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, *item.Description)
		argIdx++
	}
	if item.Price != nil {
		setParts = append(setParts, fmt.Sprintf("price = $%d", argIdx))
		args = append(args, *item.Price)
		argIdx++
	}
	if item.Warranty != nil {
		setParts = append(setParts, fmt.Sprintf("warranty = $%d", argIdx))
		args = append(args, *item.Warranty)
		argIdx++
	}

	if len(setParts) > 0 {
		args = append(args, productID)
		query := fmt.Sprintf(
			`UPDATE main SET %s, updated_at=NOW() WHERE product_id = $%d RETURNING *`,
			strings.Join(setParts, ", "),
			argIdx,
		)

		_, err = tx.ExecContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("%s: update main error: %w", op, err)
		}
	}

	if item.Media != nil {
		setParts = nil
		args = nil
		argIdx = 1

		if item.Media.MainPhoto != nil {
			setParts = append(setParts, fmt.Sprintf("main_photo = $%d", argIdx))
			args = append(args, *item.Media.MainPhoto)
			argIdx++
		}

		if item.Media.AddPhoto != nil {
			setParts = append(setParts, fmt.Sprintf("add_photo = $%d", argIdx))
			args = append(args, *item.Media.AddPhoto)
			argIdx++
		}

		if len(setParts) > 0 {
			args = append(args, productID)
			query := fmt.Sprintf(
				`UPDATE media SET %s WHERE product_id = $%d`,
				strings.Join(setParts, ", "),
				len(args),
			)

			_, err = tx.ExecContext(ctx, query, args...)
			if err != nil {
				return fmt.Errorf("%s: update media error: %w", op, err)
			}
		}
	}

	return nil
}

func (r *Repo) DeleteFromRedis(ctx context.Context, productID string) error {

	key := "products_db:" + productID

	err := r.RDB.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("redis delete error: %w", err)
	}

	return nil
}

func (r *Repo) DeleteFromDB(ctx context.Context, productID string) error {

	const op = "products.repo.DeleteFromDB"

	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%s: ❌ begin tx failed: %w", op, err)
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		} else {
			_ = tx.Commit()
		}
	}()

	query2 := `DELETE FROM media WHERE product_id=$1;`

	_, err = tx.ExecContext(ctx, query2, productID)
	if err != nil {
		return fmt.Errorf("%s media table: delete error: %w", op, err)
	}

	query1 := `DELETE FROM main WHERE product_id=$1;`

	res, err := tx.ExecContext(ctx, query1, productID)
	if err != nil {
		return fmt.Errorf("%s main table: delete item error: %w", op, err)
	}

	row, _ := res.RowsAffected()
	if row == 0 {
		return fmt.Errorf("%s main table: %v", op, errs.ErrNotFound)
	}

	return nil
}

func (r *Repo) GetFromRedis(ctx context.Context, ids []string) ([]service.Item, []string) {

	const op = "products.repo.GetFromRedis"

	var foundItems []service.Item
	var missingIDs []string

	for _, i := range ids {
		key := "products_db:" + i

		itemBytes, err := r.RDB.Get(ctx, key).Bytes()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				missingIDs = append(missingIDs, i)
				continue
			}

			missingIDs = append(missingIDs, i)
			r.log.Error("❗redis get error", zap.Error(err),
				zap.String(constants.LogComponentKey, op))
			continue
		}

		var item service.Item
		err = json.Unmarshal(itemBytes, &item)
		if err != nil {
			missingIDs = append(missingIDs, i)
			continue
		}

		foundItems = append(foundItems, item)
	}

	return foundItems, missingIDs
}

func (r *Repo) GetFromDB(ctx context.Context, ids []string) ([]service.Item, error) {

	const op = "products.repo.GetFromDB"

	query := `SELECT m.product_id, m.article, m.name, m.description, m.price, 
       m.warranty, md.main_photo, md.add_photo 
		FROM main m  
		JOIN media md USING (product_id)
		WHERE m.product_id = ANY($1);`

	rows, err := r.DB.QueryContext(ctx, query, pq.StringArray(ids))
	if err != nil {
		return nil, fmt.Errorf("%s: select error: %w", op, err)
	}
	defer func() { _ = rows.Close() }()

	resultMap := make(map[string]service.Item)

	for rows.Next() {
		var item service.Item

		err = rows.Scan(
			&item.ProductID,
			&item.Article,
			&item.Name,
			&item.Description,
			&item.Price,
			&item.Warranty,
			&item.Media.MainPhoto,
			&item.Media.AddPhoto,
		)

		if err != nil {
			return nil, fmt.Errorf("%s: scan error: %w", op, err)
		}
		resultMap[item.ProductID] = item
	}

	if len(resultMap) == 0 {
		var notFoundIDs string
		for _, id := range ids {
			notFoundIDs += id
			notFoundIDs += ", "
		}

		r.log.Warn("❗no items found for given ids in DB",
			zap.String("not_found_ids", notFoundIDs),
			zap.String(constants.LogComponentKey, op))

		return []service.Item{}, nil
	}

	var items []service.Item
	for _, id := range ids {
		if item, ok := resultMap[id]; ok {
			items = append(items, item)
		}
	}

	return items, nil
}
