WORKSPACE = $(shell pwd)
PLAY_FILE ?= 

generate:
	go generate ./...

run: generate
	@go run cmd/trafficbus/*.go -f $(WORKSPACE)/testdata/rule.json

trace:
	@cat /sys/kernel/tracing/trace_pipe

# dev
playground:
	@clang -o $(WORKSPACE)/cplayground/$(PLAY_FILE) $(WORKSPACE)/cplayground/$(PLAY_FILE).c
	@$(WORKSPACE)/cplayground/$(PLAY_FILE)
	@rm -f $(WORKSPACE)/cplayground/$(PLAY_FILE)
