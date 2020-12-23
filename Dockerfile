FROM golang:1.14 as build

ENV GO111MODULE=on

WORKDIR /app
COPY . .

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o server *.go

FROM gcr.io/distroless/base
COPY --from=build /app/server /
COPY --from=build /app/index.html .
COPY --from=build /app/webauthn.crt .
COPY --from=build /app/webauthn.key .
COPY --from=build /app/tls-ca.pem .
EXPOSE 8080

ENTRYPOINT ["/server"]