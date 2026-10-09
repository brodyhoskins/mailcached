package wbxml

import (
	"bytes"
	"testing"
)

func TestTokens(t *testing.T) {
	for name, want := range map[string][2]byte{
		"AirSync:HeartbeatInterval": {0, 0x29}, "AirSync:ApplicationData": {0, 0x1d}, "Email:FlagStatus": {2, 0x3b},
		"Email:DisallowNewTimeProposal": {2, 0x3f}, "Move:DstMsgId": {5, 0x0c}, "GetItemEstimate:Status": {6, 0x0e},
		"FolderHierarchy:Count": {7, 0x17}, "Ping:MaxFolders": {13, 0x0d}, "Provision:Hash": {14, 0x3a},
		"Provision:MaxEmailAgeFilter": {14, 0x2a}, "ItemOperations:MoveAlways": {20, 0x19}, "AirSyncBase:Preview": {17, 0x18},
		"ComposeMail:Mime": {21, 0x10}, "Settings:SmtpAddress": {18, 0x1f},
	} {
		if got := tokens[name]; got != want {
			t.Errorf("%s = %#v, want %#v", name, got, want)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	doc := El("AirSync:Sync", El("AirSync:Collections", El("AirSync:Collection",
		Tx("AirSync:SyncKey", "0"), Tx("AirSync:CollectionId", "m1"),
		El("AirSync:Commands", El("AirSync:Add", Tx("AirSync:ServerId", "m1:7"),
			El("AirSync:ApplicationData", Tx("Email:Subject", "Hi ünïcode"), El("AirSyncBase:Body",
				Tx("AirSyncBase:Type", "2"), Op("AirSyncBase:Data", bytes.Repeat([]byte{0, 1, 2}, 100)))))),
		El("AirSync:GetChanges"))))
	b, err := Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	c := got.Child("Collections").Child("Collection")
	if c.Value("SyncKey") != "0" || c.Child("GetChanges") == nil {
		t.Fatalf("%+v", c)
	}
	ad := c.Child("Commands").Child("Add").Child("ApplicationData")
	if ad.Value("Email:Subject") != "Hi ünïcode" || len(ad.Child("AirSyncBase:Body").Child("Data").Data) != 300 {
		t.Fatalf("%+v", ad)
	}
}
