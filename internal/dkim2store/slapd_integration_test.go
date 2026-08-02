package dkim2store

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/croessner/opendkim-manage-go/internal/dkim2model"
)

const requireSlapdEnvironment = "OPENDKIM_MANAGE_REQUIRE_SLAPD"

// TestLDAPV2RepositoryAgainstSlapd proves the crash-resumable repository contract against a real isolated server.
func TestLDAPV2RepositoryAgainstSlapd(t *testing.T) {
	if os.Getenv(requireSlapdEnvironment) != "1" {
		t.Skip("set OPENDKIM_MANAGE_REQUIRE_SLAPD=1 to require the isolated slapd gate")
	}
	executor := startIsolatedSlapd(t)
	repository := newSlapdRepository(t, executor)
	history, err := repository.LoadRetainedHistory(context.Background(), 8)
	if err != nil {
		t.Fatalf("empty retained-history read failed: %v", err)
	}
	if !history.Complete || len(history.Roots) != 0 {
		t.Fatal("empty retained-history read did not prove a complete empty generation container")
	}
	current := fixedStoreGeneration(t, 1, dkim2model.DatasetStateStaging)
	defer func() { _ = current.Close() }()
	if err := repository.Publish(context.Background(), 0, current); err != nil {
		t.Fatalf("bootstrap publication failed: %v", err)
	}
	loaded, err := repository.LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("current readback failed: %v", err)
	}
	assertCompleteBinaryRoundTrip(t, current, loaded)

	candidate := successorGeneration(t, loaded, 2)
	_ = loaded.Close()
	defer func() { _ = candidate.Close() }()
	prepared, err := repository.Stage(context.Background(), candidate, 8)
	if err != nil {
		t.Fatalf("staging failed: %v", err)
	}
	_ = prepared.Close()

	// A fresh repository must recover after a crash between root commit and pointer switch.
	restarted := newSlapdRepository(t, executor)
	if err := restarted.commitGeneration(context.Background(), 2); err != nil {
		t.Fatalf("root commit failed: %v", err)
	}
	resumed := newSlapdRepository(t, executor)
	pending, err := resumed.LoadPending(context.Background(), 2, 8)
	if err != nil {
		t.Fatalf("committed-unreachable recovery failed: %v", err)
	}
	stored, err := pending.Generation()
	if err != nil {
		t.Fatal(err)
	}
	if pending.ExpectedCurrent() != 1 || pending.ObservedCurrent() != 1 || stored.State() != dkim2model.DatasetStateCommitted {
		_ = stored.Close()
		_ = pending.Close()
		t.Fatal("recovered candidate did not preserve the forward-only fence")
	}
	assertCompleteBinaryRoundTrip(t, candidate, stored)
	_ = stored.Close()
	_ = pending.Close()
	if err := resumed.CommitAndSwitch(context.Background(), 2, 8); err != nil {
		t.Fatalf("resumed pointer switch failed: %v", err)
	}
	activated, err := resumed.LoadCurrent(context.Background())
	if err != nil {
		t.Fatalf("activated readback failed: %v", err)
	}
	defer func() { _ = activated.Close() }()
	assertCompleteBinaryRoundTrip(t, candidate, activated)

	// A stale RFC 4528 pointer assertion must fail without a second pointer write.
	stale := ldap.NewModifyRequest("cn=current,"+executor.baseDN, nil)
	stale.Replace(attributeGeneration, []string{"3"})
	control, err := newAssertionControl(metadataAssertion(1, datasetStateCommitted))
	if err != nil {
		t.Fatal(err)
	}
	stale.Controls = []ldap.Control{control}
	if _, err := executor.ModifyRequest(stale); !ldap.IsErrorWithCode(err, ldap.LDAPResultAssertionFailed) {
		t.Fatalf("stale pointer assertion error = %v", err)
	}
	unchanged, err := resumed.LoadCurrent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unchanged.Close() }()
	if unchanged.Number() != 2 {
		t.Fatalf("failed assertion changed current to generation %d", unchanged.Number())
	}
}

type slapdRequestExecutor struct {
	baseDN string
	conn   *ldap.Conn
}

func (e *slapdRequestExecutor) BaseDN() string { return e.baseDN }

func (e *slapdRequestExecutor) SearchRequest(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return e.conn.Search(request)
}

func (e *slapdRequestExecutor) AddRequest(request *ldap.AddRequest) error {
	return e.conn.Add(request)
}

func (e *slapdRequestExecutor) ModifyRequest(request *ldap.ModifyRequest) (*ldap.ModifyResult, error) {
	return e.conn.ModifyWithResult(request)
}

// startIsolatedSlapd starts one loopback-only temporary server using the exact pinned test schema.
func startIsolatedSlapd(t *testing.T) *slapdRequestExecutor {
	t.Helper()
	slapd := requireExecutable(t, []string{
		"/usr/local/opt/openldap/libexec/slapd",
		"/usr/libexec/slapd",
		"/opt/homebrew/opt/openldap/libexec/slapd",
		"/usr/sbin/slapd",
	})
	schemaDirectory := requireDirectory(t, []string{
		"/usr/local/etc/openldap/schema",
		"/etc/openldap/schema",
		"/etc/ldap/schema",
		"/opt/homebrew/etc/openldap/schema",
	})
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal("cannot resolve the isolated schema fixture")
	}
	pinnedSchema := filepath.Join(workspace, "testdata", "rnsdkim2.schema")
	if _, err := os.Stat(pinnedSchema); err != nil {
		t.Fatal("the exact pinned DKIM2 schema fixture is unavailable")
	}

	temporary := t.TempDir()
	databaseDirectory := filepath.Join(temporary, "database")
	if err := os.Mkdir(databaseDirectory, 0o700); err != nil {
		t.Fatal("cannot create the isolated slapd database")
	}
	configuration := fmt.Sprintf(`include %s
include %s
include %s
pidfile %s
argsfile %s
database mdb
maxsize 33554432
suffix "dc=example,dc=test"
rootdn "cn=admin,dc=example,dc=test"
rootpw integration-placeholder
directory %s
index objectClass eq
access to * by dn.exact="cn=admin,dc=example,dc=test" manage by * none
`, filepath.Join(schemaDirectory, "core.schema"), filepath.Join(schemaDirectory, "cosine.schema"), pinnedSchema,
		filepath.Join(temporary, "slapd.pid"), filepath.Join(temporary, "slapd.args"), databaseDirectory)
	configurationPath := filepath.Join(temporary, "slapd.conf")
	if err := os.WriteFile(configurationPath, []byte(configuration), 0o600); err != nil {
		t.Fatal("cannot write the isolated slapd configuration")
	}

	validation := exec.Command(slapd, "-Ttest", "-u", "-f", configurationPath)
	var validationOutput bytes.Buffer
	validation.Stdout = &validationOutput
	validation.Stderr = &validationOutput
	if err := validation.Run(); err != nil {
		t.Fatal("the isolated slapd configuration or pinned schema was rejected")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot reserve an isolated loopback listener")
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal("cannot release the isolated loopback listener")
	}

	var output bytes.Buffer
	command := exec.Command(slapd, "-d", "0", "-f", configurationPath, "-h", "ldap://"+address)
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal("cannot start the required isolated slapd")
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		select {
		case <-waited:
		case <-time.After(2 * time.Second):
		}
	})

	var connection *ldap.Conn
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-waited:
			t.Fatal("the required isolated slapd exited during startup")
		default:
		}
		connection, err = ldap.DialURL("ldap://"+address, ldap.DialWithDialer(&net.Dialer{Timeout: 200 * time.Millisecond}))
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if connection == nil {
		t.Fatal("the required isolated slapd did not accept loopback connections")
	}
	connection.SetTimeout(5 * time.Second)
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.Bind("cn=admin,dc=example,dc=test", "integration-placeholder"); err != nil {
		t.Fatal("cannot bind to the required isolated slapd")
	}
	addSlapdFixtureEntry(t, connection, "dc=example,dc=test", map[string][]string{
		"objectClass": {"top", "dcObject", "organization"}, "dc": {"example"}, "o": {"example"},
	})
	addSlapdFixtureEntry(t, connection, "ou=dkim2,dc=example,dc=test", map[string][]string{
		"objectClass": {"top", "organizationalUnit"}, "ou": {"dkim2"},
	})
	addSlapdFixtureEntry(t, connection, "ou=generations,ou=dkim2,dc=example,dc=test", map[string][]string{
		"objectClass": {"top", "organizationalUnit"}, "ou": {"generations"},
	})
	return &slapdRequestExecutor{baseDN: "ou=dkim2,dc=example,dc=test", conn: connection}
}

func newSlapdRepository(t *testing.T, executor *slapdRequestExecutor) *LDAPRepository {
	t.Helper()
	repository, err := NewLDAPRepository(executor)
	if err != nil {
		t.Fatal("cannot bind the repository to the isolated slapd")
	}
	return repository
}

func requireExecutable(t *testing.T, candidates []string) string {
	t.Helper()
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	t.Fatal("the required slapd executable is unavailable")
	return ""
}

func requireDirectory(t *testing.T, candidates []string) string {
	t.Helper()
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	t.Fatal("the required OpenLDAP schema directory is unavailable")
	return ""
}

func addSlapdFixtureEntry(t *testing.T, connection *ldap.Conn, dn string, attributes map[string][]string) {
	t.Helper()
	request := ldap.NewAddRequest(dn, nil)
	for attribute, values := range attributes {
		request.Attribute(attribute, values)
	}
	if err := connection.Add(request); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		t.Fatal("cannot initialize the synthetic slapd fixture")
	}
}
