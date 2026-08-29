package ux

import (
	"golang.org/x/time/rate"
)

type Profile int

const (
	ProfileSneaky Profile = iota
	ProfileNormal
	ProfileAggressive
)

func ProfileFromString(s string) Profile {
	switch s {
	case "sneaky":
		return ProfileSneaky
	case "aggressive":
		return ProfileAggressive
	default:
		return ProfileNormal
	}
}

func NewLimiter(p Profile) *rate.Limiter {
	switch p {
	case ProfileSneaky:
		return rate.NewLimiter(rate.Limit(1), 1)
	case ProfileAggressive:
		return rate.NewLimiter(rate.Limit(1e9), 1e9)
	default:
		return rate.NewLimiter(rate.Limit(50), 50)
	}
}
