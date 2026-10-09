package engine

import (
	"slices"
	"testing"
)

func TestNotifyTap(t *testing.T) {
	woke := 0
	tap := newNotifyTap(func() { woke++ })
	// The engine's own STATUS: its answer is not a notification.
	tap.wrote([]byte("A1 STATUS \"Sent\" (MESSAGES)\r\n"))
	tap.read([]byte("* STATUS \"Sent\" (MESSAGES 3)\r\nA1 OK done\r\n"))
	// A message body that looks like a response is passed over.
	tap.read([]byte("* 1 FETCH (BODY[] {32}\r\n* STATUS Fake (MESSAGES 1)\r\n\r\n)\r\n"))
	// Notifications, one split across reads, one in modified UTF-7.
	tap.read([]byte("* STATUS Archive (MESS"))
	tap.read([]byte("AGES 2 UIDNEXT 3)\r\n* STATUS \"Entw&APw-rfe\" (UIDNEXT 9)\r\n"))
	tap.read([]byte("* LIST () \"/\" \"New\"\r\n"))
	names, all, list := tap.take()
	slices.Sort(names)
	if !slices.Equal(names, []string{"Archive", "Entwürfe"}) || all || !list || woke == 0 {
		t.Fatalf("names %q, all %v, list %v, woke %d", names, all, list, woke)
	}
	// A LIST of the engine's own, with STATUS in it.
	tap.wrote([]byte("A2 LIST \"\" \"*\" RETURN (STATUS (MESSAGES))\r\n"))
	tap.read([]byte("* LIST () \"/\" INBOX\r\n* STATUS INBOX (MESSAGES 1)\r\nA2 OK\r\n"))
	// A name the tap cannot read: every folder.
	tap.read([]byte("* STATUS {4}\r\nWork (MESSAGES 1)\r\n"))
	names, all, list = tap.take()
	if len(names) != 0 || !all || list {
		t.Fatalf("names %q, all %v, list %v", names, all, list)
	}
}
