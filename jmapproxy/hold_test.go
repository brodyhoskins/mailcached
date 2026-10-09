package jmapproxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
	"github.com/brodyhoskins/mailcached/internal/jmap"
	"github.com/brodyhoskins/mailcached/internal/sealtest"
)

// locker holds sealed mail while locked.
type locker struct {
	sealtest.Sealer
	locked atomic.Bool
}

func (l *locker) Read(ctx context.Context, raw []byte) ([]byte, engine.ReadStatus) {
	if l.locked.Load() && sealtest.IsSealed(raw) {
		return raw, engine.ReadHold
	}
	return l.Sealer.Read(ctx, raw)
}

// TestHeldNotInJMAP checks that a held message is no JMAP Email, and
// becomes one, as created, when released.
func TestHeldNotInJMAP(t *testing.T) {
	l := &locker{}
	l.locked.Store(true)
	e := newEnv(t, l)
	var got jmap.GetResponse[jmap.Email]
	e.call(t, "Email/get", jmap.GetArgs{AccountID: e.acct, IDs: []jmap.ID{}}, &got)
	state := got.State
	a := e.eng.Account(enginetest.User)
	eventually(t, "the first sync", func() bool { return !a.Since().IsZero() })

	data := sealtest.Seal(plain("held-1@test", "Held", "Wait for it."))
	up := e.upstream(t)
	cmd := up.Append("INBOX", int64(len(data)), &imap.AppendOptions{Time: time.Now().Add(time.Minute)})
	cmd.Write(data)
	cmd.Close()
	if _, err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the hold", func() bool { return a.Held() == 1 })
	if n := e.mailboxes(t)["INBOX"].TotalEmails; n != 0 {
		t.Fatalf("INBOX counts %d emails while one is held", n)
	}
	var ch jmap.ChangesResponse
	e.call(t, "Email/changes", jmap.ChangesArgs{AccountID: e.acct, SinceState: state}, &ch)
	if len(ch.Created) != 0 {
		t.Fatalf("a held message shows in Email/changes: %+v", ch)
	}

	l.locked.Store(false)
	e.eng.Recheck()
	eventually(t, "the release", func() bool { return a.Held() == 0 })
	e.call(t, "Email/changes", jmap.ChangesArgs{AccountID: e.acct, SinceState: state}, &ch)
	if len(ch.Created) != 1 {
		t.Fatalf("after the release: %+v", ch)
	}
}
