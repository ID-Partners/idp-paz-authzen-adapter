# authzen-extauthz: Envoy ext_authz (gRPC) -> AuthZEN PDP bridge, the
# agentgateway counterpart of the Kong authzen-pdp plugin.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /authzen-extauthz .

FROM alpine:3.20
COPY --from=build /authzen-extauthz /usr/local/bin/authzen-extauthz
EXPOSE 9191
ENTRYPOINT ["/usr/local/bin/authzen-extauthz"]
