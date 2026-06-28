package rabbitmq

import (
	"context"
	"fmt"
	"github.com/rabbitmq/amqp091-go"
)

type Publisher interface {
	Publish(ctx context.Context, eventType string, payload []byte) error
}

type RabbitPublisher struct {
	mq *RabbitMQ
}

func NewRabbitPublisher(mq *RabbitMQ) *RabbitPublisher {
	return &RabbitPublisher{mq: mq}
}

func (p *RabbitPublisher) Publish(ctx context.Context, eventType string, payload []byte) error {

	msg := amqp091.Publishing{
		ContentType: "application/json",
		Body:        payload,
		Type:        eventType}

	err := p.mq.ch.PublishWithContext(ctx, "", p.mq.q.Name, false, false, msg)
	if err != nil {
		return fmt.Errorf("publish with context error: %w", err)
	}

	return nil
}
