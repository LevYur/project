# build stage
FROM golang:1.24-alpine AS build

WORKDIR /app

COPY ../../go.mod ../../go.sum ./
RUN go mod download

COPY ../../ ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/gateway-service ./gateway/cmd/main.go

# runtime stage
FROM alpine:3.20

WORKDIR /app

COPY --from=build /app/gateway-service .

EXPOSE 7970

CMD ["./main"]