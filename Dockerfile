FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /chipin ./cmd/chipin

FROM gcr.io/distroless/static-debian12
COPY --from=build /chipin /chipin
WORKDIR /app
ENV CHIPIN_LISTEN=:8080 CHIPIN_DATA=/data CHIPIN_PUBLIC=/app/public
EXPOSE 8080
ENTRYPOINT ["/chipin", "serve"]
