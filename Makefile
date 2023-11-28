PLAY_FILE ?= 

generate:
	go generate ./...

run: generate
	@go run cmd/trafficbus/*.go

trace:
	@cat /sys/kernel/tracing/trace_pipe

# dev
playground:
	@clang -o ./cplayground/$(PLAY_FILE) ./cplayground/$(PLAY_FILE).c
	@./cplayground/$(PLAY_FILE)
	@rm -f ./cplayground/$(PLAY_FILE)
