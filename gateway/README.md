# Gateway API

Шлюз для аутентификации и регистрации пользователей.  
Принимает запросы от клиента и проксирует их в сервис аутентификации (`auth-service`).  
Поддерживает регистрацию и авторизацию пользователей.

---

## Функциональность
- Регистрация пользователя (`POST /api/auth/register`)
- Авторизация (`POST /api/auth/login`)
- Swagger-документация по адресу `/api/swagger/index.html`

---

## Технологии
- Go 1.24.5
- [Gin](https://github.com/gin-gonic/gin) — HTTP-фреймворк
- [Zap](https://github.com/uber-go/zap) — логирование
- [swaggo/swag](https://github.com/swaggo/swag) — Swagger-документация
- Docker / Docker Compose
- Prometheus — метрики и мониторинг

---

## Конфигурация
Конфигурация задаётся через `.env` или переменные окружения.  
Скопируйте файл `.env.example` в `.env.prod` и отредактируйте под своё окружение.

---

## Метрики Prometheus

Доступны по адресу /metrics.

- http_requests_total / CounterVec /	method, path, status /	Общее количество HTTP-запросов, обработанных шлюзом 
- http_request_duration_seconds /	HistogramVec /	method, path	/ Время обработки HTTP-запросов 
- auth_refresh_success_total /	Counter /	—	/ Количество успешных обновлений access_token 
- auth_refresh_failed_total	/ CounterVec /	reason	/ Количество неудачных попыток обновить access_token 
- gateway_invalid_login_request_total /	CounterVec /	reason	/ Количество некорректных запросов логина (ошибки валидации, отсутствующие поля и т.д.)
- gateway_invalid_register_request_total /	CounterVec /	reason	/ Количество некорректных запросов регистрации

---

## Swagger-документация
Swagger доступен по адресу:
http://gateway-service:7971/api/gateway/swagger/index.html

---

## Запуск через Docker
docker-compose up --build

---

##  Graceful shutdown

Приложение корректно завершает работу при получении сигналов SIGINT / SIGTERM:
- Завершает активные запросы