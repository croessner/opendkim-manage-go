package types

import "fmt"

type DKIMKeyType int

const (
	DKIMKeyTypeUnknown DKIMKeyType = iota
	DKIMKeyTypeRSA
	DKIMKeyTypeED25519
	DKIMKeyTypeBoth
	DKIMKeyTypeRevoked
)

func (t DKIMKeyType) String() string {
	switch t {
	case DKIMKeyTypeRSA:
		return "rsa"
	case DKIMKeyTypeED25519:
		return "ed25519"
	case DKIMKeyTypeBoth:
		return "both"
	case DKIMKeyTypeRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

func ParseDKIMKeyType(s string) (DKIMKeyType, error) {
	switch s {
	case "rsa":
		return DKIMKeyTypeRSA, nil
	case "ed25519":
		return DKIMKeyTypeED25519, nil
	case "both":
		return DKIMKeyTypeBoth, nil
	case "revoked":
		return DKIMKeyTypeRevoked, nil
	default:
		return DKIMKeyTypeUnknown, fmt.Errorf("unsupported key type %q", s)
	}
}

type DKIMActiveState int

const (
	DKIMDisabled DKIMActiveState = iota
	DKIMEnabled
)

type DKIMRevokeState int

const (
	RevokeDisabled DKIMRevokeState = iota
	RevokeEnabled
)

type Scheme struct {
	DKIM                 string
	DomainClass          string
	DomainRelatedObject  string
	DKIMKey              string
	DKIMKeyType          string
	DKIMIdentity         string
	DKIMSelector         string
	DKIMActive           string
	DKIMDomain           string
	AssociatedDomain     string
	DestinationIndicator string
	ServiceType          string
	CreateTimestamp      string
	ModifyTimestamp      string
}

func DefaultScheme() Scheme {
	return Scheme{
		DKIM:                 "DKIM",
		DomainClass:          "domain",
		DomainRelatedObject:  "domainRelatedObject",
		DKIMKey:              "DKIMKey",
		DKIMKeyType:          "DKIMKeyType",
		DKIMIdentity:         "DKIMIdentity",
		DKIMSelector:         "DKIMSelector",
		DKIMActive:           "DKIMActive",
		DKIMDomain:           "DKIMDomain",
		AssociatedDomain:     "associatedDomain",
		DestinationIndicator: "destinationIndicator",
		ServiceType:          "description",
		CreateTimestamp:      "createTimestamp",
		ModifyTimestamp:      "modifyTimestamp",
	}
}
