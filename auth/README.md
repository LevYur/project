# Gateway API

Сервис аутентификации и управления пользователями.
Обрабатывает запросы от gateway-service, выполняет бизнес-логику входа, регистрации и обновления токенов, взаимодействует с базой данных и брокером сообщений (RabbitMQ).

---

## Функциональность
- Регистрация нового пользователя (POST /auth/register)
- Аутентификация пользователя (POST /auth/login)
- Обновление пары токенов (POST /auth/refresh)
- Отправка событий о создании пользователей в RabbitMQ (users.created)
- Система outbox для гарантированной доставки сообщений
- Метрики Prometheus (/metrics)
- Логирование и трассировка запросов

---

## Архитектура

Сервис построен по многослойной архитектуре:

- server : HTTP-роутинг и обработчики (Gin)
- service : бизнес-логика (авторизация, регистрация, refresh)
- repository : работа с PostgreSQL
- middleware : логирование, метрики, recover, timeout, request ID
- tokens : генерация и валидация JWT токенов
- rabbitmq : публикация событий в очередь
- outbox : механизм надёжной доставки сообщений

---

## Технологии
- Go 1.24.5
- [Gin](https://github.com/gin-gonic/gin) — HTTP-фреймворк
- [Zap](https://github.com/uber-go/zap) — логирование
- [swaggo/swag](https://github.com/swaggo/swag) — Swagger-документация
- Docker / Docker Compose
- RabbitMQ — брокер сообщений
- PostgreSQL — хранилище пользователей
- Prometheus — метрики и мониторинг

---

## Конфигурация
Конфигурация задаётся через `.env` или переменные окружения.  
Скопируйте файл `.env.example` в `.env.prod` и отредактируйте под своё окружение.

---

## Метрики Prometheus

Доступны по адресу /metrics.

- http_requests_total / Counter	/ method, path, status	/ Общее количество HTTP-запросов
- http_request_duration_seconds	/ Histogram /	method, path /	Время обработки HTTP-запросов 
- auth_logins_success_total	/ Counter /	—	/ Количество успешных логинов 
- auth_logins_failed_total /	CounterVec /	reason /	Количество неудачных логинов (по причине)
- auth_registers_success_total /	Counter /	—	/ Количество успешных регистраций 
- auth_registers_failed_total /	CounterVec /	reason /	Количество неудачных регистраций (по причине)
- auth_refresh_success_total /	Counter	/ —	/ Количество успешных обновлений токенов 
- auth_refresh_failed_total	/ CounterVec	/ reason /	Количество неудачных попыток обновить токен (по причине)

---

## Swagger-документация

Swagger доступен по адресу:
http://auth-service:7971/api/auth/swagger/index.html

---

## Запуск через Docker
docker-compose up --build

---

##  Graceful shutdown

Приложение корректно завершает работу при получении сигналов SIGINT / SIGTERM:
- Завершает активные запросы
- Останавливает воркер Outbox
- Закрывает соединение с БД и RabbitMQ