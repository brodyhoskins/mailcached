package engine

import (
	"errors"
	"fmt"
	"testing"

	"github.com/emersion/go-imap/v2"
)

// TestCrowdedGreeting checks that a provider turning a connection away in
// its greeting for too many connections counts as crowded, not as
// rejected credentials.
func TestCrowdedGreeting(t *testing.T) {
	err := fmt.Errorf("IMAP greeting: %w", &imap.Error{Type: imap.StatusResponseTypeBye, Text: "[LIMIT] Too many connections"})
	if !crowded(err) || !unreached(err) {
		t.Fatal("a BYE [LIMIT] greeting does not count as crowded")
	}
	if errors.Is(rejected(err), ErrLoginRejected) {
		t.Fatal("a BYE [LIMIT] greeting counts as rejected credentials")
	}
}
