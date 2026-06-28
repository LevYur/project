package producer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"productsmodule/internal/broker/kafka/events"
	"productsmodule/internal/config"
	"time"
)

type ProducerInterface interface {
	PublishProductUpdated(productID string) error
	PublishProductDeleted(productID string) error
	Close()
}

type KafkaProducer struct {
	writer  *kafka.Writer
	timeout time.Duration
	log     *zap.Logger
	// topic  string
}

func New(cfg *config.Config, log *zap.Logger) *KafkaProducer {

	writer := &kafka.Writer{
		Addr:         kafka.TCP(cfg.KafkaProducer.Brokers...),
		Topic:        cfg.Topic,
		RequiredAcks: kafka.RequireAll,
		Balancer:     &kafka.Hash{},
		BatchTimeout: time.Millisecond * 5,
	}

	return &KafkaProducer{writer: writer, log: log, timeout: cfg.KafkaProducer.Timeout}
}

func (p *KafkaProducer) PublishProductUpdated(productID string) error {

	const op = "products.broker.kafka.producer.PublishProductUpdated"

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	event := events.ProductEvent{
		Type:      events.ProductUpdated,
		ProductID: productID,
		Payload:   nil,
		Timestamp: time.Now().UTC(),
	}

	bytesEvent, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("%s:❗marshal event error: %w", op, err)
	}

	msg := kafka.Message{
		Key:   []byte(productID),
		Value: bytesEvent,
		Time:  event.Timestamp,
	}

	err = p.writer.WriteMessages(ctx, msg)
	if err != nil {
		return fmt.Errorf("%s:❗publish message error: %w", op, err)
	}

	return nil
}

func (p *KafkaProducer) PublishProductDeleted(productID string) error {

	const op = "products.broker.kafka.producer.PublishProductDeleted"

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	event := events.ProductEvent{
		Type:      events.ProductDeleted,
		ProductID: productID,
		Payload:   nil,
		Timestamp: time.Now().UTC(),
	}

	bytesEvent, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("%s:❗marshal event error: %w", op, err)
	}

	msg := kafka.Message{
		Key:   []byte(productID),
		Value: bytesEvent,
		Time:  event.Timestamp,
	}

	err = p.writer.WriteMessages(ctx, msg)
	if err != nil {
		return fmt.Errorf("%s:❗publish message error: %w", op, err)
	}

	return nil
}

func (p *KafkaProducer) Close() {
	err := p.writer.Close()
	if err != nil {
		p.log.Error("❗failed to close kafka producer")
	}
}
