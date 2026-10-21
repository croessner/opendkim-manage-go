package dkim2store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/ldapstore"
)

// activationMarkerExecutor models the monotonic LDAP privilege without permitting replacement.
type activationMarkerExecutor struct {
	*fakeExecutor
	loseReply bool
	writes    int
}

// TestActivationMarkerAgainstSlapd verifies real LDAP add-only authorization and restart readback.
func TestActivationMarkerAgainstSlapd(t *testing.T) {
	if os.Getenv(requireSlapdEnvironment) != "1" {
		t.Skip("set OPENDKIM_MANAGE_REQUIRE_SLAPD=1 to require the isolated slapd gate")
	}
	executor := startIsolatedSlapdWithACL(t, `access to attrs=dkim2WasActive
    by dn.exact="cn=activator,dc=example,dc=test" =dcsra
    by * none
access to attrs=userPassword by anonymous auth by * none
access to * by dn.exact="cn=activator,dc=example,dc=test" read by * none`)
	addSlapdFixtureEntry(t, executor.conn, "cn=activator,dc=example,dc=test", map[string][]string{
		"objectClass": {"top", "organizationalRole", "simpleSecurityObject"},
		"cn":          {"activator"}, "userPassword": {"integration-placeholder"},
	})
	pointer := currentPointer{schema: dkim2model.SchemaVersionV3, generation: 2, state: datasetStateCommitted}
	copy(pointer.digest[:], bytes.Repeat([]byte{7}, 32))
	root := "dkim2Generation=2,ou=generations," + executor.baseDN
	addSlapdFixtureEntry(t, executor.conn, root, map[string][]string{
		attributeObjectClass: {classTop, classDataset, classAdministrativeMetadata},
		attributeCN:          {"generation-2"}, attributeSchemaVersion: {pointer.schema},
		attributeGeneration: {"2"}, attributeDatasetState: {pointer.state},
		attributeCandidateDigest: {string(pointer.digest[:])},
	})
	if err := executor.conn.Bind("cn=activator,dc=example,dc=test", "integration-placeholder"); err != nil {
		t.Fatal(err)
	}
	denied := ldap.NewModifyRequest(root, nil)
	denied.Replace(attributeWasActive, []string{"TRUE"})
	if err := executor.conn.Modify(denied); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		t.Fatalf("replacement unexpectedly allowed: %v", err)
	}
	passwordDirectory := t.TempDir()
	if err := os.Chmod(passwordDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(passwordDirectory, "activation-password")
	if err := os.WriteFile(passwordFile, []byte("integration-placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.LDAP.URI = executor.url + "/" + executor.baseDN
	cfg.LDAP.AllowInsecure = true
	cfg.DKIM2.LDAPOperationTimeoutSeconds = 5
	cfg.DKIM2.AuthorityPasswordMaxBytes = 1024
	authority := config.DKIM2LDAPAuthority{BindDN: "cn=activator,dc=example,dc=test", PasswordFile: passwordFile}
	for attempt := 0; attempt < 2; attempt++ {
		client, err := ldapstore.NewAuthorityClient(cfg, authority, ldapstore.AuthorityActivation)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.EnsureConnected(); err != nil {
			t.Fatalf("isolated authority connection: %v", err)
		}
		repository, err := NewLDAPRepository(client, testLimits())
		if err != nil {
			t.Fatal(err)
		}
		markErr := repository.markSourceWasActive(context.Background(), pointer)
		closeErr := client.Close()
		if err := errors.Join(markErr, closeErr); err != nil {
			t.Fatal(err)
		}
	}
}

// ModifyRequest rejects marker deletion/replacement and preserves native duplicate semantics.
func (e *activationMarkerExecutor) ModifyRequest(request *ldap.ModifyRequest) (*ldap.ModifyResult, error) {
	for _, change := range request.Changes {
		if change.Modification.Type != attributeWasActive {
			continue
		}
		e.writes++
		if change.Operation != ldap.AddAttribute {
			return nil, ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("marker is add-only"))
		}
		if len(e.entries[dnKey(request.DN)].GetAttributeValues(attributeWasActive)) != 0 {
			return nil, ldap.NewError(ldap.LDAPResultAttributeOrValueExists, errors.New("marker already exists"))
		}
	}
	result, err := e.fakeExecutor.ModifyRequest(request)
	if err == nil && e.loseReply {
		e.loseReply = false
		return nil, errors.New("response lost after commit")
	}
	return result, err
}

// activationMarkerFixture creates one committed v3 source with a bound immutable digest.
func activationMarkerFixture(t *testing.T) (*LDAPRepository, *activationMarkerExecutor, currentPointer) {
	t.Helper()
	fake := newFakeExecutor(testBaseDN)
	executor := &activationMarkerExecutor{fakeExecutor: fake}
	repository, err := NewLDAPRepository(executor, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	pointer := currentPointer{schema: dkim2model.SchemaVersionV3, generation: 2, state: datasetStateCommitted}
	copy(pointer.digest[:], bytes.Repeat([]byte{7}, 32))
	root := metadataEntry(repository.generationRoot(2), 2, datasetStateCommitted)
	setEntryAttribute(root, attributeSchemaVersion, []string{pointer.schema})
	setEntryAttribute(root, attributeCandidateDigest, []string{string(pointer.digest[:])})
	setEntryAttribute(root, attributeObjectClass, []string{classTop, classDataset, classAdministrativeMetadata})
	fake.put(root)
	return repository, executor, pointer
}

// TestActivationMarkerUsesAddOnlyPrivilegesAndResumes proves the first v3-to-v3 rotation and replay.
func TestActivationMarkerUsesAddOnlyPrivilegesAndResumes(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "lost-reply"}[lost], func(t *testing.T) {
			repository, executor, source := activationMarkerFixture(t)
			executor.loseReply = lost
			if err := repository.markSourceWasActive(context.Background(), source); err != nil {
				t.Fatal(err)
			}
			restarted, err := NewLDAPRepository(executor, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			if err := restarted.markSourceWasActive(context.Background(), source); err != nil {
				t.Fatal(err)
			}
			if executor.writes != 1 {
				t.Fatal("replay performed another marker mutation")
			}
			assertCriticalAssertion(t, executor.modifies[0])
		})
	}
}

// TestActivationMarkerRejectsChangedOrNonmonotonicEvidence preserves immutable roots and unexpected states.
func TestActivationMarkerRejectsChangedOrNonmonotonicEvidence(t *testing.T) {
	for _, change := range []struct{ name, attribute, value string }{
		{"digest", attributeCandidateDigest, string(bytes.Repeat([]byte{8}, 32))},
		{"generation", attributeGeneration, "3"},
		{"state", attributeDatasetState, datasetStateStaging},
		{"false-marker", attributeWasActive, "FALSE"},
	} {
		t.Run(change.name, func(t *testing.T) {
			repository, executor, source := activationMarkerFixture(t)
			setEntryAttribute(executor.entries[dnKey(repository.generationRoot(2))], change.attribute, []string{change.value})
			if err := repository.markSourceWasActive(context.Background(), source); err == nil {
				t.Fatal("changed source accepted")
			}
			if executor.writes != 0 {
				t.Fatal("changed source attempted mutation")
			}
		})
	}
}
