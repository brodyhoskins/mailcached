package easproxy

// MoveItems, ItemOperations and GetAttachment.

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"

	"github.com/brodyhoskins/mailcached/engine"
)

// The MoveItems statuses of MS-ASCMD 2.2.3.177.9.
const (
	moveBadSource = 1
	moveBadDest   = 2
	moveDone      = 3
	moveSame      = 4
	moveFailed    = 5
)

func (req *request) moveItems() (*node, error) {
	if req.doc == nil {
		return nil, httpStatus(http.StatusBadRequest)
	}
	a := req.c.acct
	var out []*node
	for _, mv := range req.doc.Children("Move") {
		src, dst := mv.Value("SrcFldId"), mv.Value("DstFldId")
		srcMsg := mv.Value("SrcMsgId")
		resp := func(status int, dstMsg string) *node {
			kids := []*node{tx("Move:SrcMsgId", srcMsg), tx("Move:Status", strconv.Itoa(status))}
			if dstMsg != "" {
				kids = append(kids, tx("Move:DstMsgId", dstMsg))
			}
			return el("Move:Response", kids...)
		}
		folder, uid, ok := parseItemID(srcMsg)
		if !ok || folder != src {
			out = append(out, resp(moveBadSource, ""))
			continue
		}
		if src == dst {
			out = append(out, resp(moveSame, ""))
			continue
		}
		a.Lock()
		sm, dm := folderByID(a, src), folderByID(a, dst)
		var dstName string
		if dm != nil {
			dstName = dm.Name()
		}
		a.Unlock()
		switch {
		case sm == nil:
			out = append(out, resp(moveBadSource, ""))
			continue
		case dm == nil:
			out = append(out, resp(moveBadDest, ""))
			continue
		}
		req.dv.mu.Lock()
		moved, _, err := a.Move(sm, func(msg *engine.Message) bool { return msg.UID() == uid }, dstName)
		if err == nil && len(moved) == 1 {
			// The device moved it itself: neither folder's next Sync
			// reports it.
			if cs := req.dv.coll(src); cs != nil {
				delete(cs.Items, uid)
			}
			req.noteMoved(moved, dstName)
			_ = req.dv.save()
		}
		req.dv.mu.Unlock()
		switch {
		case err != nil:
			out = append(out, resp(moveFailed, ""))
		case len(moved) == 0:
			out = append(out, resp(moveBadSource, ""))
		default:
			out = append(out, resp(moveDone, itemID(dst, moved[0].ToUID)))
		}
	}
	return el("Move:MoveItems", out...), nil
}

// attachmentData returns an attachment's content and type, by its
// FileReference.
func (req *request) attachmentData(ref string) ([]byte, string, bool, error) {
	folder, uid, path, ok := parseFileRef(ref)
	if !ok {
		return nil, "", false, nil
	}
	a := req.c.acct
	a.Lock()
	m := folderByID(a, folder)
	a.Unlock()
	if m == nil {
		return nil, "", false, nil
	}
	msg := messageAt(a, m, uid)
	if msg == nil {
		return nil, "", false, nil
	}
	data, err := a.Download([]*engine.Message{msg}, nil)
	if err != nil {
		return nil, "", false, err
	}
	raw, ok := data[msg]
	if !ok {
		return nil, "", false, nil
	}
	b, t, ok := partData(raw, path)
	return b, t, ok, nil
}

// getAttachment answers GetAttachment (ActiveSync 12): the attachment,
// raw.
func (req *request) getAttachment(w http.ResponseWriter) ([]byte, error) {
	b, t, ok, err := req.attachmentData(req.params["AttachmentName"])
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, httpStatus(http.StatusNotFound)
	}
	w.Header().Set("Content-Type", t)
	return b, nil
}

// The ItemOperations statuses of MS-ASCMD 2.2.3.177.7.
const (
	itemOK        = 1
	itemProtocol  = 2
	itemServer    = 3
	itemBadRef    = 6
	itemNotFound  = 15
	itemBadRange  = 8
	itemNoSupport = 18 // the action is not supported
)

func (req *request) itemOperations() (*node, error) {
	if req.doc == nil {
		return el("ItemOperations:ItemOperations", tx("ItemOperations:Status", strconv.Itoa(itemProtocol))), nil
	}
	var out []*node
	for _, op := range req.doc.Kids {
		switch {
		case op.Is("Fetch"):
			out = append(out, req.itemFetch(op))
		case op.Is("EmptyFolderContents"):
			out = append(out, req.emptyFolder(op))
		default:
			name := op.Name
			out = append(out, el(name, tx("ItemOperations:Status", strconv.Itoa(itemNoSupport))))
		}
	}
	return el("ItemOperations:ItemOperations", tx("ItemOperations:Status", "1"),
		el("ItemOperations:Response", out...)), nil
}

// itemFetch fetches a message or an attachment.
func (req *request) itemFetch(op *node) *node {
	fail := func(status int, kids ...*node) *node {
		return el("ItemOperations:Fetch", append([]*node{tx("ItemOperations:Status", strconv.Itoa(status))}, kids...)...)
	}
	if ref := op.Value("AirSyncBase:FileReference"); ref != "" {
		refNode := tx("AirSyncBase:FileReference", ref)
		b, t, ok, err := req.attachmentData(ref)
		switch {
		case err != nil:
			return fail(itemServer, refNode)
		case !ok:
			return fail(itemBadRef, refNode)
		}
		total := len(b)
		props := []*node{tx("AirSyncBase:ContentType", t)}
		if rng := op.Child("Options").Value("Range"); rng != "" {
			from, to, ok := parseRange(rng, total)
			if !ok {
				return fail(itemBadRange, refNode)
			}
			b = b[from:to]
			props = append(props, tx("ItemOperations:Range", strconv.Itoa(from)+"-"+strconv.Itoa(max(to-1, from))),
				tx("ItemOperations:Total", strconv.Itoa(total)))
		}
		props = append(props, tx("ItemOperations:Data", base64.StdEncoding.EncodeToString(b)))
		return el("ItemOperations:Fetch", tx("ItemOperations:Status", "1"), refNode,
			el("ItemOperations:Properties", props...))
	}
	id := op.Value("AirSync:ServerId")
	coll := op.Value("AirSync:CollectionId")
	ids := []*node{tx("AirSync:CollectionId", coll), tx("AirSync:ServerId", id)}
	folder, uid, ok := parseItemID(id)
	if !ok || (coll != "" && folder != coll) {
		return fail(itemNotFound, ids...)
	}
	a := req.c.acct
	a.Lock()
	m := folderByID(a, folder)
	a.Unlock()
	if m == nil {
		return fail(itemNotFound, ids...)
	}
	msg := messageAt(a, m, uid)
	if msg == nil {
		return fail(itemNotFound, ids...)
	}
	opts := parseOptions(op.Child("Options"))
	if opts == nil {
		opts = &syncOptions{}
	}
	ad, err := req.appData(msg, opts, folder)
	if err != nil {
		return fail(itemServer, ids...)
	}
	ad.Name = "ItemOperations:Properties"
	return el("ItemOperations:Fetch", append([]*node{tx("ItemOperations:Status", "1")},
		append(ids, tx("AirSync:Class", "Email"), ad)...)...)
}

// parseRange reads a Range, "first-last", inclusive, into slice bounds.
func parseRange(r string, total int) (int, int, bool) {
	var from, to int
	if _, err := fmt.Sscanf(r, "%d-%d", &from, &to); err != nil || from < 0 || to < from {
		return 0, 0, false
	}
	if from >= total {
		return total, total, true
	}
	return from, min(to+1, total), true
}

// emptyFolder deletes every message of a folder.
func (req *request) emptyFolder(op *node) *node {
	id := op.Value("AirSync:CollectionId")
	a := req.c.acct
	a.Lock()
	m := folderByID(a, id)
	a.Unlock()
	if m == nil {
		return el("ItemOperations:EmptyFolderContents", tx("ItemOperations:Status", strconv.Itoa(itemNotFound)),
			tx("AirSync:CollectionId", id))
	}
	a.Expunge(m, func(*engine.Message) bool { return true })
	return el("ItemOperations:EmptyFolderContents", tx("ItemOperations:Status", "1"), tx("AirSync:CollectionId", id))
}
