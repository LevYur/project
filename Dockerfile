# build stage
FROM golang:1.24-alpine AS build

WORKDIR /app

# копируем go.mod/go.sum
COPY go.mod go.sum ./
RUN go mod download

# копируем весь проект
COPY . .

# билдим бинарь gateway
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/gateway-service ./gateway/cmd/main.go

# билдим бинарь auth
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/auth-service ./auth/cmd/main.go

# runtime stage для gateway
FROM alpine:3.20 AS gateway-runtime
WORKDIR /app
COPY --from=build /app/gateway-service .
EXPOSE 7970
CMD ["./gateway-service"]

# runtime stage для auth
FROM alpine:3.20 AS auth-runtime
WORKDIR /app
COPY --from=build /app/auth-service .
EXPOSE 7971
CMD ["./auth-service"]
