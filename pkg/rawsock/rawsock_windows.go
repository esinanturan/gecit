package rawsock

import "fmt"

func New() (RawSocket, error) {
	// TODO: Phase 3 — Windows uses WinDivert for packet injection
	return nil, fmt.Errorf("raw socket not yet implemented on Windows")
}
