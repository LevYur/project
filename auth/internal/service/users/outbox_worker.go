package users

import (
	"context"
	"github.com/LevYur/project/auth/pkg/constants"
	"go.uber.org/zap"
	"time"
)

func (s *Service) RunOutboxWorker(ctx context.Context) {

	const op = "auth.internal.service.users.StartOutboxWorker"

	log, ok := ctx.Value(constants.LoggerKey).(*zap.Logger)
	if !ok {
		log = zap.L()
	}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	log.Info("🚀 outbox worker begin checking DB", zap.String(constants.LogComponentKey, op))

	for {
		select {
		case <-ctx.Done():
			log.Info("🛑 outbox worker stopped by context",
				zap.String(constants.LogComponentKey, op))
			return

		case <-ticker.C:
			log.Info("🚀 outbox worker tick", zap.String(constants.LogComponentKey, op))

			events, err := s.outboxRepo.GetUnprocessedEvents(ctx)
			if err != nil {
				log.Info("failed to get unprocessed events",
					zap.Error(err),
					zap.String(constants.LogComponentKey, op))

				continue
			}

			for _, e := range events {
				err = s.broker.Publish(ctx, e.EventType, e.Payload)
				if err != nil {
					log.Error("failed to publish event",
						zap.Error(err),
						zap.String(constants.LogComponentKey, op))

					continue
				}

				err = s.outboxRepo.MarkEventProcessed(ctx, e.ID)
				if err != nil {
					log.Error("failed to mark event processed",
						zap.Error(err),
						zap.String(constants.LogComponentKey, op))

				}
			}
		}
	}
}
