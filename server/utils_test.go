package server

import "testing"

func TestTemplate_IsDefaultPath(t *testing.T) {
	testCases := map[string]bool{
		"./config.json":         true,
		"./configs/config.json": false,
	}
	for k, v := range testCases {
		result := IsDefaultPath(&k)
		if result != v {
			t.Errorf("Got %t for path %s but expected %t", result, k, v)
		}
	}
}
