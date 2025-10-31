# -------------------
# Build stage
# -------------------
FROM golang:1.24-alpine AS build

WORKDIR /app

# копируем go.mod/go.sum из корня проекта
COPY go.mod go.sum ./
RUN go mod download

# копируем весь проект
COPY . .

# строим бинарь gateway
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/gateway-service ./gateway/cmd/main.go

# строим бинарь auth
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/auth-service ./auth/cmd/main.go

# -------------------
# Runtime stage
# -------------------
FROM alpine:3.20

WORKDIR /app

# копируем бинарники из build stage
COPY --from=build /app/gateway-service .
COPY --from=build /app/auth-service .

EXPOSE 7970
EXPOSE 7971

# по умолчанию запускаем shell, контейнеры будут запускаться через docker-compose
CMD ["sh"]