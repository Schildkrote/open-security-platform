package session

import "testing"

func TestSessionRecordAndVerify(t *testing.T) {
	s := Start("s1", "alice", "db")
	s.Record("command", "SELECT 1")
	s.Record("output", "1")
	s.End()

	if !s.Verify() {
		t.Fatal("transcript should verify")
	}
	if len(s.Entries) != 4 { // start, command, output, end
		t.Fatalf("expected 4 entries, got %d", len(s.Entries))
	}
	if s.Transcript() == "" {
		t.Fatal("transcript should not be empty")
	}
}

func TestSessionTamperDetection(t *testing.T) {
	s := Start("s1", "alice", "db")
	s.Record("command", "rm -rf /")
	s.End()

	s.Entries[1].Data = "SELECT 1" // tamper
	if s.Verify() {
		t.Fatal("tampered transcript should fail verification")
	}
}

func TestClosedSessionIgnoresWrites(t *testing.T) {
	s := Start("s1", "alice", "db")
	s.End()
	before := len(s.Entries)
	s.Record("command", "late")
	if len(s.Entries) != before {
		t.Fatal("closed session should ignore new records")
	}
}
