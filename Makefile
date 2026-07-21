MODULE := ngstone
BIN_DIR := bin
LDFLAGS :=

DEPLOY_HOST ?= ngstone.site
DEPLOY_USER ?= root
DEPLOY_BIN_PATH ?= /usr/local/bin/ngstoned

.PHONY: build
build:
	mkdir -p $(BIN_DIR)
	go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/ngstoned ./cmd/ngstoned
	go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/ngstone ./cmd/ngstone

.PHONY: test
test:
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	go test ./... -race -count=1

.PHONY: cross
cross:
	mkdir -p $(BIN_DIR)/linux_amd64
	GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/linux_amd64/ngstoned ./cmd/ngstoned
	GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/linux_amd64/ngstone ./cmd/ngstone

.PHONY: deploy
deploy: test cross
	scp $(BIN_DIR)/linux_amd64/ngstoned $(DEPLOY_USER)@$(DEPLOY_HOST):$(DEPLOY_BIN_PATH).new
	ssh $(DEPLOY_USER)@$(DEPLOY_HOST) ' \
		mv $(DEPLOY_BIN_PATH).new $(DEPLOY_BIN_PATH) && \
		chmod 755 $(DEPLOY_BIN_PATH) && \
		systemctl restart ngstoned && \
		systemctl status --no-pager ngstoned \
	'

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
