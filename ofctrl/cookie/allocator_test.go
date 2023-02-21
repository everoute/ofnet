package cookie

import (
	"testing"
)

func TestAllocateCookie(t *testing.T) {
	allocator := NewAllocator(0)

	cookie := allocator.RequestCookie()
	if cookie != 0x1 {
		t.Errorf("request cookie fail, expect 0x1, got %x", cookie)
	}

	cookie = allocator.RequestCookie()
	if cookie != 0x2 {
		t.Errorf("request cookie fail, expect 0x2, got %x", cookie)
	}

	allocator.SetFixedMask(0x10)

	cookie = allocator.RequestCookie()
	if cookie != 0x13 {
		t.Errorf("request cookie fail, expect 0x13, got %x", cookie)
	}

	allocator = NewAllocator(1)

	cookie = allocator.RequestCookie()
	if cookie != 0x10000001 {
		t.Errorf("request cookie fail, expect 0x10000001, got %x", cookie)
	}

	cookie = allocator.RequestCookie()
	if cookie != 0x10000002 {
		t.Errorf("request cookie fail, expect 0x10000002, got %x", cookie)
	}

	allocator.SetFixedMask(0x100000000)

	cookie = allocator.RequestCookie()
	if cookie != 0x110000003 {
		t.Errorf("request cookie fail, expect 0x110000003, got %x", cookie)
	}
}
