package capi

import (
	"regexp"
	"strings"
)

func Authorize(target, pattern string) bool {
	if target == "" || pattern == "" {
		return false
	}

	if strings.HasPrefix(pattern, "re/") {
		matched, err := regexp.MatchString(pattern[3:], target)
		if err != nil {
			return false
		}
		return matched
	}

	return target == pattern
}
