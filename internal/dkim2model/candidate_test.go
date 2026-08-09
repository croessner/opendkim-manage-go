package dkim2model

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCandidateMetadataCampaignDigestGolden(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x2a}, ed25519.SeedSize))
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := NewKeyPair(AlgorithmEd25519SHA256, privateDER, publicDER)
	clear(privateDER)
	clear(publicDER)
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pair.Close() }()
	handle, _ := NewHandle(2, "handle-ed")
	profile, _ := NewProfile(2, "profile-ed", "example.test", RecordStatusActive, time.Time{}, time.Time{})
	credential, _ := NewCredential(2, profile.ID(), "selector-ed", AlgorithmEd25519SHA256, pair.PublicSPKIDER(), handle.ID())
	policy, _ := NewPolicy(2, "tenant", "example.test", ProfileUseOriginator, profile.ID(), RecordStatusActive, RolloutEnforce, CompatibilityStrict, "")
	material, _ := NewKeyMaterial(2, policy.TenantID(), policy.SigningDomain(), policy.Use(), handle.ID(), pair)
	defer func() { _ = material.Close() }()
	generation, err := NewGenerationWithState(2, DatasetStateStaging, []Handle{handle}, []Profile{profile}, []Credential{credential}, []Policy{policy}, []*KeyMaterial{material})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = generation.Close() }()
	metadata, err := NewCandidateMetadata("aebagbafaydqqcikbmga2dqpca", 1, generation)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(metadata.DigestBytes()); got != "22ee26e2c80c612bbc655691288b286367940728d8f081d04fd848d3cf4bca77" {
		t.Fatalf("campaign digest = %s", got)
	}
}

func TestCandidateMetadataUsesV3DigestContractAndIsProtected(t *testing.T) {
	generation := activeBindingGeneration(t, 2, AlgorithmEd25519SHA256)
	defer func() { _ = generation.Close() }()
	metadata, err := NewCandidateMetadata("aebagbafaydqqcikbmga2dqpca", 1, generation)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SchemaVersion() != SchemaVersionV3 || metadata.SourceGeneration() != 1 ||
		metadata.Generation() != generation.Number() || len(metadata.DigestBytes()) != CandidateDigestBytes {
		t.Fatal("incomplete v3 metadata")
	}
	clone, err := NewCandidateMetadata("aebagbafaydqqcikbmga2dqpca", 1, generation)
	if err != nil || !metadata.DigestEqual(clone) {
		t.Fatal("candidate digest is not deterministic")
	}
	encoded, _ := json.Marshal(metadata)
	for _, output := range []string{fmt.Sprintf("%v", metadata), fmt.Sprintf("%#v", metadata), string(encoded)} {
		if strings.Contains(output, "aebagbafaydqqcikbmga2dqpca") || bytes.Contains([]byte(output), metadata.DigestBytes()) {
			t.Fatal("protected candidate metadata reached generic formatting")
		}
	}
}

func TestCandidateMetadataDigestChangesForPrivateKeyOnlyChange(t *testing.T) {
	left := activeBindingGeneration(t, 2, AlgorithmEd25519SHA256)
	defer func() { _ = left.Close() }()
	right := activeBindingGeneration(t, 2, AlgorithmEd25519SHA256)
	defer func() { _ = right.Close() }()
	leftMetadata, err := NewCandidateMetadata("aebagbafaydqqcikbmga2dqpca", 1, left)
	if err != nil {
		t.Fatal(err)
	}
	rightMetadata, err := NewCandidateMetadata("aebagbafaydqqcikbmga2dqpca", 1, right)
	if err != nil {
		t.Fatal(err)
	}
	if leftMetadata.DigestEqual(rightMetadata) {
		t.Fatal("private candidate difference was not digest-bound")
	}
}
