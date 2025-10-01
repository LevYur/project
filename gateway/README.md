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

---

## Конфигурация
Конфигурация задаётся через `config.yaml` или переменные окружения.  
Скопируйте файл `config.example.yaml` в `config.yaml` и отредактируйте под своё окружение.