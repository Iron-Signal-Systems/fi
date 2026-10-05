package backendinstall

import "testing"

func TestSystemCommandPath(t *testing.T) {
	expected := map[string]string{
		"freebsd-version": "/bin/freebsd-version",
		"getent":          "/usr/bin/getent",
		"hostname":        "/bin/hostname",
		"ifconfig":        "/sbin/ifconfig",
		"jls":             "/usr/sbin/jls",
		"uname":           "/usr/bin/uname",
		"zfs":             "/sbin/zfs",
		"zpool":           "/sbin/zpool",
	}

	for name, want := range expected {
		got, err := systemCommandPath(name)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}

		if got != want {
			t.Fatalf("%s: got %q, want %q", name, got, want)
		}
	}

	if _, err := systemCommandPath("sh"); err == nil {
		t.Fatal("systemCommandPath(sh) expected rejection")
	}
}
