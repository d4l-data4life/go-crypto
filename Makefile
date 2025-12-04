LINT_VERSION := v2.0

lint:
	docker run --rm \
		-v $(shell pwd):/app -w /app \
		golangci/golangci-lint:${LINT_VERSION} \
		golangci-lint run -v

test: lint test-gh-action

test-gh-action: ## Run tests natively in verbose mode
	go test -timeout 300s -cover -covermode=atomic -v ./... 2>&1 | tee test-result.out
