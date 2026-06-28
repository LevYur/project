package products

import (
	"cartmodule/internal/constants"
	"context"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"time"
)

type Consumer struct {
	reader  *kafka.Reader
	handler *Handler
	decoder *Decoder
	log     *zap.Logger
}

func NewConsumer(log *zap.Logger, brokers []string, topic, groupID string, handler *Handler,
	decoder *Decoder) *Consumer {

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:         brokers,
		Topic:           topic,
		GroupID:         groupID,
		StartOffset:     kafka.FirstOffset,
		MinBytes:        1,
		MaxBytes:        10e6,
		ReadLagInterval: -1,
	})

	return &Consumer{
		reader:  reader,
		handler: handler,
		decoder: decoder,
		log:     log,
	}
}

func (c *Consumer) MustRun(ctx context.Context) {

	const op = "internal.broker.consumer.kafka.products"

	c.log.Info("👉 [kafka] consumer started", zap.String(constants.LogComponentKey, op))

	for {
		select {
		case <-ctx.Done():
			c.log.Info("[kafka] context canceled, shutting down consumer",
				zap.String(constants.LogComponentKey, op))

			_ = c.reader.Close()
			return

		default:

		}

		msg, err := c.reader.FetchMessage(ctx)
		if err != nil { // network errors / timeout
			c.log.Error("❗[kafka] fetch error, will retry",
				zap.String(constants.LogComponentKey, op),
				zap.String(constants.LogKafkaTopicIDKey, msg.Topic),
				zap.Error(err))

			time.Sleep(time.Second) // retry
			continue
		}

		event, err := c.decoder.Decode(msg.Value)
		if err != nil { // network errors / timeout
			c.log.Error("❗[kafka] decode error — skipping message",
				zap.String(constants.LogComponentKey, op),
				zap.String(constants.LogKafkaTopicIDKey, msg.Topic),
				zap.Error(err))

			_ = c.reader.CommitMessages(ctx, msg) // skip invalid message → admit offset
			continue
		}

		err = c.handler.CacheInvalidationHandle(ctx, event)
		if err != nil {
			c.log.Error("❗[kafka] cache invalidation handle error",
				zap.String(constants.LogComponentKey, op),
				zap.String(constants.LogKafkaTopicIDKey, msg.Topic),
				zap.Error(err),
				zap.String(constants.LogProductIDKey, event.ProductID))

			_ = c.reader.CommitMessages(ctx, msg)
			continue
		}

		err = c.reader.CommitMessages(ctx, msg)
		if err != nil {
			c.log.Error("❗[kafka] failed — will retry",
				zap.String(constants.LogComponentKey, op),
				zap.String(constants.LogKafkaTopicIDKey, msg.Topic),
				zap.Error(err))

			time.Sleep(200 * time.Millisecond)
			continue
		}
	}
}
