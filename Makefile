generate:
	go generate ./...

run: generate
	@go run cmd/trafficbus/*.go

trace:
	@cat /sys/kernel/tracing/trace_pipe
