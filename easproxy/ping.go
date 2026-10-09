package easproxy

// Ping: a device names folders and waits, up to its heartbeat, for any of
// them to change. That is push: the engine's change log wakes the Ping
// the moment the account changes.

import (
	"strconv"
	"time"

	"github.com/brodyhoskins/mailcached/engine"
)

// Heartbeat limits, in seconds, and the most folders a Ping may name.
const (
	minHeartbeat = 60
	maxHeartbeat = 3540
	maxFolders   = 300
)

// The Ping statuses of MS-ASCMD 2.2.3.177.11.
const (
	pingExpired      = 1
	pingChanges      = 2
	pingMissing      = 3
	pingBadHeartbeat = 5
	pingTooMany      = 6
	pingFolderSync   = 7
)

func pingStatus(status int, kids ...*node) *node {
	return el("Ping:Ping", append([]*node{tx("Ping:Status", strconv.Itoa(status))}, kids...)...)
}

func (req *request) ping() (*node, error) {
	dv := req.dv
	dv.mu.Lock()
	heartbeat := dv.st.PingHeartbeat
	folders := dv.st.PingFolders
	if req.doc != nil {
		if h := req.doc.Value("HeartbeatInterval"); h != "" {
			heartbeat = atoi(h)
		}
		if fs := req.doc.Child("Folders"); fs != nil {
			folders = nil
			for _, f := range fs.Children("Folder") {
				folders = append(folders, f.Value("Id"))
			}
		}
	}
	dv.mu.Unlock()
	switch {
	case heartbeat == 0 || len(folders) == 0:
		return pingStatus(pingMissing), nil
	case heartbeat < minHeartbeat:
		return pingStatus(pingBadHeartbeat, tx("Ping:HeartbeatInterval", strconv.Itoa(minHeartbeat))), nil
	case heartbeat > maxHeartbeat:
		return pingStatus(pingBadHeartbeat, tx("Ping:HeartbeatInterval", strconv.Itoa(maxHeartbeat))), nil
	case len(folders) > maxFolders:
		return pingStatus(pingTooMany, tx("Ping:MaxFolders", strconv.Itoa(maxFolders))), nil
	}
	dv.mu.Lock()
	dv.st.PingHeartbeat, dv.st.PingFolders = heartbeat, folders
	err := dv.save()
	dv.mu.Unlock()
	if err != nil {
		return nil, err
	}

	// A newer request of the device ends this one.
	stop := make(chan struct{})
	dv.pingMu.Lock()
	if dv.ping != nil {
		close(dv.ping)
	}
	dv.ping = stop
	dv.pingMu.Unlock()
	defer func() {
		dv.pingMu.Lock()
		if dv.ping == stop {
			dv.ping = nil
		}
		dv.pingMu.Unlock()
	}()

	a := req.c.acct
	// Have the engine check the folders that are stale.
	a.Lock()
	var names []string
	for _, id := range folders {
		if m := folderByID(a, id); m != nil {
			names = append(names, m.Name())
		}
	}
	a.Unlock()
	for _, name := range names {
		_, _ = a.MailboxFor(name)
	}

	deadline := time.NewTimer(time.Duration(heartbeat) * time.Second)
	defer deadline.Stop()
	quit := req.s.quitting()
	for {
		known, hms := req.pingSnapshot(folders)
		a.Lock()
		wake := a.Changed()
		changed, hierarchy := pingCheck(a, folders, known, hms)
		a.Unlock()
		if hierarchy {
			return pingStatus(pingFolderSync), nil
		}
		if len(changed) > 0 {
			var ids []*node
			for _, id := range changed {
				ids = append(ids, tx("Ping:Folder", id))
			}
			return pingStatus(pingChanges, el("Ping:Folders", ids...)), nil
		}
		select {
		case <-wake:
		case <-deadline.C:
			return pingStatus(pingExpired), nil
		case <-stop:
			return pingStatus(pingExpired), nil
		case <-quit:
			return pingStatus(pingExpired), nil
		case <-req.r.Context().Done():
			return nil, nil
		}
	}
}

// pingSnapshot copies what the device has: its folders, and each named
// folder's HIGHESTMODSEQ when it last had all of it (absent if never).
// It is taken before the account lock, which is never held when the
// device's is taken.
func (req *request) pingSnapshot(folders []string) (map[string]folderRec, map[string]uint64) {
	dv := req.dv
	dv.mu.Lock()
	defer dv.mu.Unlock()
	hms := map[string]uint64{}
	for _, id := range folders {
		if cs := dv.coll(id); cs != nil {
			hms[id] = cs.HMS
		}
	}
	return cloneFolders(dv.st.Folders), hms
}

// pingCheck returns the folders that changed since the device last had
// them all, and whether the folder list changed (lock held).
func pingCheck(a *engine.Account, folders []string, known map[string]folderRec, hms map[string]uint64) (changed []string, hierarchy bool) {
	now := currentFolders(a)
	if len(now) != len(known) {
		return nil, true
	}
	for id, f := range now {
		if known[id] != f {
			return nil, true
		}
	}
	for _, id := range folders {
		m := folderByID(a, id)
		if m == nil {
			return nil, true
		}
		if h, ok := hms[id]; !ok || a.HighestModSeq(m) != h {
			changed = append(changed, id)
		}
	}
	return changed, false
}
