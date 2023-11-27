package main

import (
	"xdp/internal/ebpf/xdp"
)

func main() {
	xdp.Run("ens3")
}
