package dkim2store

const (
	legacySchemaVersion       = "dkim2-datasource-v1"
	attributeObjectClass      = "objectClass"
	attributeCN               = "cn"
	attributeOU               = "ou"
	attributeSchemaVersion    = "dkim2SchemaVersion"
	attributeGeneration       = "dkim2Generation"
	attributeDatasetState     = "dkim2DatasetState"
	attributeHandleID         = "dkim2HandleID"
	attributeProfileID        = "dkim2ProfileID"
	attributeSigningDomain    = "dkim2SigningDomain"
	attributeRecordStatus     = "dkim2RecordStatus"
	attributeNotBefore        = "dkim2NotBefore"
	attributeNotAfter         = "dkim2NotAfter"
	attributeAlgorithm        = "dkim2Algorithm"
	attributeSelector         = "dkim2Selector"
	attributePublicKeySPKI    = "dkim2PublicKeySPKI"
	attributeTenantID         = "dkim2TenantID"
	attributeProfileUse       = "dkim2ProfileUse"
	attributeRollout          = "dkim2Rollout"
	attributeCompatibility    = "dkim2Compatibility"
	attributeFeedbackRouteID  = "dkim2FeedbackRouteID"
	attributePrivatePKCS8     = "dkim2PrivateKeyPKCS8"
	attributeCandidateDigest  = "dkim2CandidateDigest"
	attributeOperationID      = "dkim2OperationID"
	attributeWasActive        = "dkim2WasActive"
	attributeSourceGeneration = "dkim2SourceGeneration"
	attributeCreateTimestamp  = "createTimestamp"
	attributeModifyTimestamp  = "modifyTimestamp"
)

const (
	classTop                    = "top"
	classOrganizationalUnit     = "organizationalUnit"
	classDataset                = "dkim2Dataset"
	classHandle                 = "dkim2Handle"
	classProfile                = "dkim2Profile"
	classCredential             = "dkim2Credential"
	classPolicy                 = "dkim2Policy"
	classKeyMaterial            = "dkim2KeyMaterial"
	classAdministrativeMetadata = "dkim2AdministrativeMetadata"
)

const (
	datasetStateStaging   = "staging"
	datasetStateCommitted = "committed"
	assertionControlOID   = "1.3.6.1.1.12"
)

var allAttributes = []string{
	attributeObjectClass,
	attributeCN,
	attributeOU,
	attributeSchemaVersion,
	attributeGeneration,
	attributeDatasetState,
	attributeHandleID,
	attributeProfileID,
	attributeSigningDomain,
	attributeRecordStatus,
	attributeNotBefore,
	attributeNotAfter,
	attributeAlgorithm,
	attributeSelector,
	attributePublicKeySPKI,
	attributeTenantID,
	attributeProfileUse,
	attributeRollout,
	attributeCompatibility,
	attributeFeedbackRouteID,
	attributePrivatePKCS8,
	attributeCandidateDigest,
	attributeOperationID,
	attributeWasActive,
	attributeSourceGeneration,
}

var generationUnits = []string{"handles", "profiles", "credentials", "policies", "key-material"}
