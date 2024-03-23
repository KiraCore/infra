FROM golang:1.21 AS shidai-builder

WORKDIR /app

COPY ./src/shidai .

RUN CGO_ENABLED=0 go build -a -tags netgo -installsuffix cgo -o /shidai ./cmd/main.go

FROM scratch

COPY --from=shidai-builder /shidai /shidai

CMD ["/shidai"]

EXPOSE 8282
