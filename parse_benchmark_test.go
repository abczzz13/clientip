package clientip

import "testing"

func BenchmarkParseIP(b *testing.B) {
	testCases := []string{"1.1.1.1", "  1.1.1.1  ", "1.1.1.1:8080", "[2606:4700:4700::1]", "[2606:4700:4700::1]:8080", `"1.1.1.1"`}

	for _, tc := range testCases {
		b.Run(tc, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ip := parseIP(tc)
				if !ip.IsValid() {
					b.Fatal("parsing failed")
				}
			}
		})
	}
}
