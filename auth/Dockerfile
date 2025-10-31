# build stage
FROM golang:1.24-alpine AS build

WORKDIR /app

COPY ../../go.mod ../../go.sum ./
RUN go mod download

COPY ../../ ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/auth-service ./auth/cmd/main.go

# runtime stage
FROM alpine:3.20

WORKDIR /app

COPY --from=build /app/auth-service .

EXPOSE 7971

CMD ["./main"]