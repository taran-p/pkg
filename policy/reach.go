// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package policy

import "strings"

// Reach is how far a policy can go toward permitting an action on any
// resource, under any request conditions.
type Reach uint8

const (
	// ReachNone means no Allow statement can match the action.
	ReachNone Reach = iota

	// ReachPossible means an Allow statement can match the action for some
	// resource and request, and no Deny refuses it everywhere. It does not mean
	// any particular request is allowed.
	ReachPossible

	// ReachDenied means a Deny with no conditions refuses the action on every
	// resource. Merged with other policies, the action stays refused.
	ReachDenied
)

// Reach reports whether the policy could ever allow action, without a resource
// or condition values. It errs toward ReachPossible: a ReachNone or ReachDenied
// result guarantees Decide never returns AllowDecision for the action, while a
// ReachPossible result guarantees nothing.
//
// Resources and conditions on Allow statements are ignored, since some resource
// and request could satisfy them. A Deny counts only when it has no conditions
// and refuses every resource the action can name.
func (iamp *Policy) Reach(action Action) Reach {
	reach := ReachNone
	for i := range iamp.Statements {
		statement := &iamp.Statements[i]
		if !statement.matchesAction(action) {
			continue
		}
		switch statement.Effect {
		case Deny:
			if len(statement.Conditions) == 0 && statement.coversEveryResource(action) {
				return ReachDenied
			}
		case Allow:
			reach = ReachPossible
		}
	}
	return reach
}

// coversEveryResource reports whether the statement applies to action on every
// resource. It mirrors the resource handling in isAllowedFor and answers false
// wherever that handling depends on the request.
func (statement Statement) coversEveryResource(action Action) bool {
	class := statement.classify()

	// An S3 action reached through a tables statement applies only to the
	// tables form of a warehouse object.
	if class.has(classTable) && !TableAction(action).IsValid() {
		return false
	}

	if class.has(classSTS) || (class.has(classAdmin) && !class.has(classAdminResource)) {
		return true
	}

	if len(statement.NotResources) > 0 {
		return false
	}
	if len(statement.Resources) == 0 {
		return true
	}
	for resource := range statement.Resources {
		if resource.Pattern != "" && strings.Trim(resource.Pattern, "*") == "" {
			return true
		}
	}
	return false
}
