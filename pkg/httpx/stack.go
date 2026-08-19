package httpx

import "runtime"

// stack renders the current goroutine's stack, capped so a panic storm cannot
// fill the log ingestion budget.
func stack() string {
	buf := make([]byte, 8192)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}
