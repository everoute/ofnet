package cookie

import (
	"testing"
)

func TestAllocateCookie(t *testing.T) {
	allocator := NewAllocator(0)

	cookie, err := allocator.RequestCookie()
	if err != nil {
		t.Errorf("unexpectd return err %s", err)
	}
	if cookie != 0x1 {
		t.Errorf("request cookie fail, expect 0x1, got %x", cookie)
	}

	cookie, err = allocator.RequestCookie()
	if err != nil {
		t.Errorf("unexpectd return err %s", err)
	}
	if cookie != 0x2 {
		t.Errorf("request cookie fail, expect 0x2, got %x", cookie)
	}

	allocator.SetFixedMask(0x10)

	cookie, err = allocator.RequestCookie()
	if err != nil {
		t.Errorf("unexpectd return err %s", err)
	}
	if cookie != 0x13 {
		t.Errorf("request cookie fail, expect 0x13, got %x", cookie)
	}

	allocator = NewAllocator(1)

	cookie, err = allocator.RequestCookie()
	if err != nil {
		t.Errorf("unexpectd return err %s", err)
	}
	if cookie != 0x10000001 {
		t.Errorf("request cookie fail, expect 0x10000001, got %x", cookie)
	}

	cookie, err = allocator.RequestCookie()
	if err != nil {
		t.Errorf("unexpectd return err %s", err)
	}
	if cookie != 0x10000002 {
		t.Errorf("request cookie fail, expect 0x10000002, got %x", cookie)
	}

	allocator.SetFixedMask(0x100000000)

	cookie, err = allocator.RequestCookie()
	if err != nil {
		t.Errorf("unexpectd return err %s", err)
	}
	if cookie != 0x110000003 {
		t.Errorf("request cookie fail, expect 0x110000003, got %x", cookie)
	}

	allocator = NewAllocator(1, SetFlowIDRange(10, 9))
	if allocator != nil {
		t.Errorf("expect allocator is nil, but real is not")
	}

	allocator = NewAllocator(1, SetFlowIDRange(0, 9))
	if allocator != nil {
		t.Errorf("expect allocator is nil, but real is not")
	}

	allocator = NewAllocator(1, SetFlowIDRange(10, 1<<BitWidthFlowId))
	if allocator != nil {
		t.Errorf("expect allocator is nil, but real is not")
	}

	allocator = NewAllocator(1, SetFlowIDRange(10, 11))

	cookie, err = allocator.RequestCookie()
	if err != nil {
		t.Errorf("unexpectd return err %s", err)
	}
	if cookie != 0x1000000a {
		t.Errorf("request cookie fail, expect 0x1000000a , got %x", cookie)
	}
	cookie, err = allocator.RequestCookie()
	if err != nil {
		t.Errorf("unexpectd return err %s", err)
	}
	if cookie != 0x1000000b {
		t.Errorf("request cookie fail, expect 0x1000000b, got %x", cookie)
	}
	cookie, err = allocator.RequestCookie()
	if err == nil {
		t.Errorf("expect allocate cookie failed, but success")
	}

	allocator = NewAllocator(1, SetDefaultFlowIDRange())
	if allocator == nil {
		t.Errorf("new allocator failed, is unexpected")
	}
	cookie, err = allocator.RequestCookie()
	if err != nil {
		t.Errorf("unexpectd return err %s", err)
	}
	if cookie != 0x10000001 {
		t.Errorf("request cookie fail, expect 0x10000001, got %x", cookie)
	}
}
