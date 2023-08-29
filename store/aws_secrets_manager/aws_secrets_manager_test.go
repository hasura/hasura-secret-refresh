package aws_secrets_manager

import (
	"testing"
	"time"
)

func TestTemplate_GetCacheTtlFromDuration(t *testing.T) {
	testCases := map[time.Duration]int64{
		time.Microsecond: 1000,
		time.Second:      1000000000,
	}
	for k, v := range testCases {
		actualResult := GetCacheTtlFromDuration(k)
		if v != actualResult {
			t.Errorf("Expected %d for time %v but got %d", v, k, actualResult)
		}
	}
}
