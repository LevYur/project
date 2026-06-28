package rabbitmq

import (
	"github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"time"
)

type RabbitMQ struct {
	ch *amqp091.Channel
	q  amqp091.Queue
}

// MustNewRabbitMQ - creates and set up a new instance of broker
func MustNewRabbitMQ(url, queueName string) *RabbitMQ {

	log := zap.L()

	var conn *amqp091.Connection
	var err error

	for i := 0; i < 5; i++ {
		conn, err = amqp091.Dial(url)
		if err == nil {
			break
		}
		_ = conn
		log.Warn("RabbitMQ not ready, retrying...", zap.Int("attempt", i+1))
		time.Sleep(3 * time.Second)
	}

	if err != nil || conn == nil {
		log.Fatal("Failed to connect to RabbitMQ after retries")
		return nil
	}

	ch, err := conn.Channel()
	if err != nil {
		func() {
			_ = conn.Close()
		}()
		log.Fatal("create channel error: %v", zap.Error(err))
		return nil
	}

	q, err := ch.QueueDeclare(queueName, true, false, false, false, nil)
	if err != nil {
		func() {
			_ = ch.Close()
			_ = conn.Close()
		}()
		log.Fatal("declare queue error: %v", zap.Error(err))
		return nil
	}

	return &RabbitMQ{ch: ch, q: q}
}
