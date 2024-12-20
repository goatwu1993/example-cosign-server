
priv/private_key.pem:
	mkdir -p $(dir $@)
	openssl genrsa -out $@ 2048

pub/public_key.pem: priv/private_key.pem
	mkdir -p $(dir $@)
	openssl rsa -in priv/private_key.pem -pubout -out $@

.PHONY: keys
keys: priv/private_key.pem pub/public_key.pem

.PHONY: build
build: #
	mkdir -p ./tmp
	go build -o ./tmp/my-cosign-server main.go

.PHONY: all
all: #
	$(MAKE) keys
	$(MAKE) build
	#$(MAKE) run

.DEFAULT_GOAL := all