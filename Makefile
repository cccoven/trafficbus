WORKSPACE = $(shell pwd)
PLAY_FILE ?= 

generate:
	go generate ./...

trace:
	@cat /sys/kernel/tracing/trace_pipe

test:
	@go test --timeout 30s \
		github.com/cccoven/trafficbus \
		github.com/cccoven/trafficbus/internal 

# dev
playground:
	@clang -o $(WORKSPACE)/cplayground/$(PLAY_FILE) $(WORKSPACE)/cplayground/$(PLAY_FILE).c
	@$(WORKSPACE)/cplayground/$(PLAY_FILE)
	@rm -f $(WORKSPACE)/cplayground/$(PLAY_FILE)
