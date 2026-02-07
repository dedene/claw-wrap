package daemon

// credentialPreview returns a stable redacted hint for manual audits.
// It avoids exposing full short secrets. Secrets shorter than 8 characters
// are fully masked to prevent leaking too much of short API keys/tokens.
func credentialPreview(value string) string {
	runes := []rune(value)
	n := len(runes)

	switch {
	case n <= 4:
		return "****...****"
	case n < 8:
		return string(runes[0]) + "....." + string(runes[n-1])
	default:
		return string(runes[:2]) + "....." + string(runes[n-2:])
	}
}
