// Copyright (c) 2015-2023 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package wildcard

import (
	"cmp"
	"strings"
)

// MatchSimple - finds whether the text matches/satisfies the pattern string.
// supports '*' wildcard in the pattern and ? for single characters.
// Only difference to Match is that `?` at the end is optional,
// meaning `a?` pattern will match name `a`.
func MatchSimple(pattern, name string) bool {
	if pattern == "" {
		return name == pattern
	}
	if pattern == "*" {
		return true
	}
	// Do an extended wildcard '*' and '?' match.
	return deepMatchRune(name, pattern, true)
}

// Match -  finds whether the text matches/satisfies the pattern string.
// supports  '*' and '?' wildcards in the pattern string.
// unlike path.Match(), considers a path as a flat name space while matching the pattern.
// The difference is illustrated in the example here https://play.golang.org/p/Ega9qgD4Qz .
func Match(pattern, name string) (matched bool) {
	if pattern == "" {
		return name == pattern
	}
	if pattern == "*" {
		return true
	}
	// Do an extended wildcard '*' and '?' match.
	return deepMatchRune(name, pattern, false)
}

// Has returns true if the input pattern has a wildcard (pattern).
func Has(pattern string) bool {
	return cmp.Or(strings.Contains(pattern, "*"), strings.Contains(pattern, "?"))
}

func deepMatchRune(str, pattern string, simple bool) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		case '?':
			if len(str) == 0 {
				return simple
			}
		case '*':
			return len(pattern) == 1 || // Pattern ends with this star
				deepMatchRune(str, pattern[1:], simple) || // Matches next part of pattern
				(len(str) > 0 && deepMatchRune(str[1:], pattern, simple)) // Continue searching forward
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}

// MatchAsPatternPrefix matches text as a prefix of the given pattern. Examples:
//
//	| Pattern | Text    | Match Result |
//	====================================
//	| abc*    | ab      | True         |
//	| abc*    | abd     | False        |
//	| abc*c   | abcd    | True         |
//	| ab*??d  | abxxc   | True         |
//	| ab*??d  | abxc    | True         |
//	| ab??d   | abxc    | True         |
//	| ab??d   | abc     | True         |
//	| ab??d   | abcxdd  | False        |
//
// This function is only useful in some special situations.
func MatchAsPatternPrefix(pattern, text string) bool {
	for i := 0; i < len(text) && i < len(pattern); i++ {
		if pattern[i] == '*' {
			return true
		}
		if pattern[i] == '?' {
			continue
		}
		if pattern[i] != text[i] {
			return false
		}
	}
	return len(text) <= len(pattern)
}
