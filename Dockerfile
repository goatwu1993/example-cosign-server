ARG GOLANG_VERSION=1.23
FROM public.ecr.aws/docker/library/golang:${GOLANG_VERSION} AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
WORKDIR /app/
COPY main.go main.go
# echo the args
RUN CGO_ENABLED=0 go build \
        -o /app/dist/my-cosign-server \
        ./main.go

# Build image
FROM public.ecr.aws/docker/library/alpine:3.20 AS prod
WORKDIR /app
COPY --from=build /app/dist/my-cosign-server /app/my-cosign-server
EXPOSE 8000
ENV MY_COSIGN_SERVER_LISTEN_ADDRESS=0.0.0.0:8000
CMD ["/app/my-cosign-server"]
