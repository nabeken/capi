package capi

import (
	"fmt"
	"regexp"
	"strings"
)

func Authorize(target, pattern string) bool {
	if target == "" || pattern == "" {
		return false
	}

	if strings.HasPrefix(pattern, "re/") {
		matched, err := regexp.MatchString(fmt.Sprintf("(?i:%s)", pattern[3:]), target)
		if err != nil {
			return false
		}
		return matched
	}

	return strings.EqualFold(target, pattern)
}
