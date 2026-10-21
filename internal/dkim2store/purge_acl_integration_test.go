package dkim2store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/config"
	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
	"github.com/croessner/opendkim-manage-go/internal/ldapstore"
)

// TestPurgeDeleteOnlyACLAgainstSlapd exercises the shipped fragment and real separated authority clients.
func TestPurgeDeleteOnlyACLAgainstSlapd(t *testing.T) {
	if os.Getenv(requireSlapdEnvironment) != "1" {
		t.Skip("set OPENDKIM_MANAGE_REQUIRE_SLAPD=1 to require the isolated slapd gate")
	}
	fragment, err := os.ReadFile(filepath.Join("..", "..", "examples", "dkim2-purge.acl"))
	if err != nil {
		t.Fatal(err)
	}
	acl := string(fragment) + `
access to attrs=userPassword by anonymous auth by * none
access to *
    by dn.exact="cn=snapshot,dc=example,dc=test" read
    by dn.exact="cn=other,dc=example,dc=test" read
    by * none
`
	admin := startIsolatedSlapdWithACL(t, acl)
	for _, name := range []string{"snapshot", "purger", "other"} {
		addSlapdFixtureEntry(t, admin.conn, "cn="+name+",dc=example,dc=test", map[string][]string{
			"objectClass": {"top", "organizationalRole", "simpleSecurityObject"},
			"cn":          {name}, "userPassword": {"integration-placeholder"},
		})
	}
	repository := newSlapdRepository(t, admin)
	bootstrap := fixedStoreGeneration(t, 1, dkim2model.DatasetStateStaging)
	defer func() { _ = bootstrap.Close() }()
	if err := repository.Publish(context.Background(), 0, bootstrap); err != nil {
		t.Fatal(err)
	}
	for number := uint64(2); number <= 5; number++ {
		prepared := stageRetainedCampaign(t, repository, number)
		err := repository.CommitCampaignAndSwitch(context.Background(), prepared)
		_ = prepared.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	// A full staged successor and a committed but never active successor both stay protected.
	pending := stageRetainedCampaign(t, repository, 6)
	defer func() { _ = pending.Close() }()
	snapshotClient := newPurgeTestAuthority(t, admin, "snapshot", ldapstore.AuthoritySnapshot)
	snapshot, err := NewLDAPRepository(snapshotClient, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	purgeClient := newPurgeTestAuthority(t, admin, "purger", ldapstore.AuthorityPurge)
	purge, err := NewLDAPRepository(purgeClient, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	roles, err := NewRoleRepository(snapshot, repository, repository, purge)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise each veto even when its target has an activation marker.
	for _, number := range []uint64{1, 5, 6} {
		mark := ldap.NewModifyRequest(repository.generationRoot(number), nil)
		mark.Add(attributeWasActive, []string{"TRUE"})
		if err := admin.conn.Modify(mark); err != nil {
			t.Fatal(err)
		}
	}
	for _, number := range []uint64{1, 5, 6} {
		leaf := firstPurgeTestLeaf(t, admin, repository.generationRoot(number))
		if err := purgeClient.DeleteRequest(ldap.NewDelRequest(leaf, nil)); err == nil {
			t.Fatal("purger deleted legacy, current, or staging data")
		}
	}
	clearMarker := ldap.NewModifyRequest(repository.generationRoot(6), nil)
	clearMarker.Delete(attributeWasActive, nil)
	if err := admin.conn.Modify(clearMarker); err != nil {
		t.Fatal(err)
	}
	metadata, ok := pending.CampaignMetadata()
	if !ok {
		t.Fatal("missing native candidate metadata")
	}
	if err := repository.commitCampaignGeneration(context.Background(), metadata); err != nil {
		t.Fatal(err)
	}
	if err := purgeClient.DeleteRequest(ldap.NewDelRequest(firstPurgeTestLeaf(t, admin, repository.generationRoot(6)), nil)); err == nil {
		t.Fatal("purger deleted committed but never active data")
	}
	// Unknown current metadata cannot grant structural rights even for an otherwise eligible old root.
	for _, attribute := range []string{attributeDatasetState, attributeSchemaVersion} {
		original := map[string]string{attributeDatasetState: datasetStateCommitted, attributeSchemaVersion: dkim2model.SchemaVersionV3}[attribute]
		changed := ldap.NewModifyRequest(repository.currentDN, nil)
		changed.Replace(attribute, []string{"unknown"})
		if err := admin.conn.Modify(changed); err != nil {
			t.Fatal(err)
		}
		if err := purgeClient.DeleteRequest(ldap.NewDelRequest(firstPurgeTestLeaf(t, admin, repository.generationRoot(2)), nil)); err == nil {
			t.Fatal("unknown current granted purge rights")
		}
		restore := ldap.NewModifyRequest(repository.currentDN, nil)
		restore.Replace(attribute, []string{original})
		if err := admin.conn.Modify(restore); err != nil {
			t.Fatal(err)
		}
	}
	pointer, err := admin.conn.Search(ldap.NewSearchRequest(repository.currentDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 5, false, "(objectClass=*)", []string{"*"}, nil))
	if err != nil || len(pointer.Entries) != 1 {
		t.Fatal("isolated current pointer unavailable")
	}
	if err := admin.conn.Del(ldap.NewDelRequest(repository.currentDN, nil)); err != nil {
		t.Fatal(err)
	}
	if err := purgeClient.DeleteRequest(ldap.NewDelRequest(firstPurgeTestLeaf(t, admin, repository.generationRoot(2)), nil)); err == nil {
		t.Fatal("missing current granted purge rights")
	}
	restorePointer := ldap.NewAddRequest(repository.currentDN, nil)
	for _, attribute := range pointer.Entries[0].Attributes {
		restorePointer.Attribute(attribute.Name, attribute.Values)
	}
	if err := admin.conn.Add(restorePointer); err != nil {
		t.Fatal(err)
	}
	assertPurgeTestRestrictions(t, admin, repository)
	inventory, err := roles.InventoryGenerations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewGenerationPurgePlan(inventory, 2)
	if err != nil {
		t.Fatal(err)
	}
	document, err := MarshalGenerationPurgePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(document)
	interrupted := &interruptedPurgeExecutor{RequestExecutor: purgeClient, deleteExecutor: purgeClient}
	interruptedRepository, err := NewLDAPRepository(interrupted, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	roles.purge = interruptedRepository
	before := countPurgeTestEntries(t, admin, repository.generationRoot(2))
	if err := roles.DeleteGeneration(context.Background(), plan); !errors.Is(err, ErrOutcomeUncertain) {
		t.Fatalf("interrupted delete = %v", err)
	}
	if remaining := countPurgeTestEntries(t, admin, repository.generationRoot(2)); remaining != before-1 {
		t.Fatalf("first native delete was not preserved: before=%d remaining=%d calls=%d last_error=%v", before, remaining, interrupted.calls, interrupted.lastError)
	}
	// Reconnect with a fresh writer, restore the exact key-free journal, and finish root-last.
	if err := purgeClient.Close(); err != nil {
		t.Fatal(err)
	}
	restartedClient := newPurgeTestAuthority(t, admin, "purger", ldapstore.AuthorityPurge)
	roles.purge, err = NewLDAPRepository(restartedClient, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := ParseGenerationPurgePlan(document, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := roles.DeleteGeneration(context.Background(), resumed); err != nil {
		t.Fatalf("fresh authority could not resume exact partial delete: %v", err)
	}
	if err := roles.DeleteGeneration(context.Background(), resumed); err != nil {
		t.Fatalf("exact absence replay failed: %v", err)
	}
	if gone, err := snapshot.entryAbsent(context.Background(), repository.generationRoot(2)); err != nil || !gone {
		t.Fatal("generation root was not deleted last")
	}
	if _, err := roles.InventoryGenerations(context.Background()); err != nil {
		t.Fatalf("real LDAP inventory rejected preserved v2 plus v3 suffix: %v", err)
	}
	history, err := roles.LoadRetainedHistory(context.Background(), 8)
	if err != nil || !history.Complete || history.Roots[0].Schema != dkim2model.SchemaVersion {
		t.Fatalf("real LDAP history did not preserve validated legacy schema: %v", err)
	}
	resumedCandidate, err := roles.LoadPending(context.Background(), 6, 8)
	if err != nil {
		t.Fatalf("real LDAP pending recovery rejected valid retained shape: %v", err)
	}
	_ = resumedCandidate.Close()
	t.Log("real separated LDAP authorities: delete-only leaf/root, protected states, exact journal interruption/reconnect, retained legacy inventory/history/pending PASS")
}

// newPurgeTestAuthority uses a private placeholder password file and the actual purpose-bound LDAP client.
func newPurgeTestAuthority(t *testing.T, admin *slapdRequestExecutor, name string, purpose ldapstore.AuthorityPurpose) *ldapstore.Client {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	password := filepath.Join(directory, "authority-password")
	if err := os.WriteFile(password, []byte("integration-placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.LDAP.URI, cfg.LDAP.AllowInsecure = admin.url+"/"+admin.baseDN, true
	cfg.DKIM2.LDAPOperationTimeoutSeconds, cfg.DKIM2.AuthorityPasswordMaxBytes = 5, 1024
	client, err := ldapstore.NewAuthorityClient(cfg, config.DKIM2LDAPAuthority{
		BindDN: "cn=" + name + ",dc=example,dc=test", PasswordFile: password,
	}, purpose)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// firstPurgeTestLeaf obtains an existing canonical record only through the isolated fixture administrator.
func firstPurgeTestLeaf(t *testing.T, admin *slapdRequestExecutor, root string) string {
	t.Helper()
	result, err := admin.conn.Search(ldap.NewSearchRequest(root, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		64, 5, false, "(objectClass=dkim2Handle)", []string{"1.1"}, nil))
	if err != nil || len(result.Entries) == 0 {
		t.Fatal("isolated fixture handle unavailable")
	}
	return result.Entries[0].DN
}

// countPurgeTestEntries checks the actual partial-delete boundary without exposing contents.
func countPurgeTestEntries(t *testing.T, admin *slapdRequestExecutor, root string) int {
	t.Helper()
	result, err := admin.conn.Search(ldap.NewSearchRequest(root, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		64, 5, false, "(objectClass=*)", []string{"1.1"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	return len(result.Entries)
}

// assertPurgeTestRestrictions checks server privileges directly, independently of client-side request validation.
func assertPurgeTestRestrictions(t *testing.T, admin *slapdRequestExecutor, repository *LDAPRepository) {
	t.Helper()
	connection, err := ldap.DialURL(admin.url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if err := connection.Bind("cn=purger,dc=example,dc=test", "integration-placeholder"); err != nil {
		t.Fatal(err)
	}
	leaf := firstPurgeTestLeaf(t, admin, repository.generationRoot(3))
	for _, operation := range []uint{ldap.AddAttribute, ldap.DeleteAttribute, ldap.ReplaceAttribute} {
		request := ldap.NewModifyRequest(leaf, nil)
		request.Changes = []ldap.Change{{Operation: operation, Modification: ldap.PartialAttribute{Type: attributeHandleID, Vals: []string{"changed"}}}}
		if err := connection.Modify(request); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			t.Fatalf("purger attribute operation was not denied by the server: %v", err)
		}
	}
	add := ldap.NewAddRequest("ou=extra,"+repository.generationRoot(3), nil)
	add.Attribute("objectClass", []string{"top", "organizationalUnit"})
	add.Attribute("ou", []string{"extra"})
	if err := connection.Add(add); !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		t.Fatalf("purger add was not denied by the server: %v", err)
	}
	result, err := connection.Search(ldap.NewSearchRequest(repository.generationRoot(3), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		64, 5, false, "(objectClass=*)", []string{attributePrivatePKCS8}, nil))
	if err == nil && len(result.Entries) != 0 {
		t.Fatal("purger acquired directory or private-material visibility")
	}
	if err := connection.Del(ldap.NewDelRequest("cn=other,dc=example,dc=test", nil)); err == nil {
		t.Fatal("purger deleted outside the managed generation subtree")
	}
	if err := connection.Bind("cn=other,dc=example,dc=test", "integration-placeholder"); err != nil {
		t.Fatal(err)
	}
	result, err = connection.Search(ldap.NewSearchRequest(leaf, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		1, 5, false, "(objectClass=*)", []string{attributeHandleID}, nil))
	if err != nil || len(result.Entries) != 1 || strings.TrimSpace(result.Entries[0].GetAttributeValue(attributeHandleID)) == "" {
		t.Fatal("purge fragment shadowed another authority's existing read permission")
	}
	if err := connection.Del(ldap.NewDelRequest(leaf, nil)); err == nil {
		t.Fatal("purge fragment granted delete to another authority")
	}
}

// interruptedPurgeExecutor stops before the second request after one native LDAP deletion.
type interruptedPurgeExecutor struct {
	ldapstore.RequestExecutor
	deleteExecutor deletionExecutor
	calls          int
	lastError      error
}

// DeleteRequest preserves one real committed deletion and exposes a deterministic process interruption boundary.
func (e *interruptedPurgeExecutor) DeleteRequest(request *ldap.DelRequest) error {
	e.calls++
	if e.calls == 2 {
		return ErrUnavailable
	}
	e.lastError = e.deleteExecutor.DeleteRequest(request)
	return e.lastError
}
