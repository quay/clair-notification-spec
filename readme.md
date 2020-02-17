# ClairV4 Notifications

ClairV4 must provide a notification system to inform interested parties that new vulnerabilities were discovered and the manifests affected by said vulnerabilities.  

# Implementation

To implement notifications several systems must be developed and work together.  
* Vulnerability Update Diffs
* Affected Manifests Report
* Notifier Service

The following sections describes each in detail.  

## Vulnerability Update Diffs

Updaters are responsible for fetching vulnerability databases, parsing its contents, and writing vulnerabilities to the database.  
To support notifications, `libvuln` must also inform clients whether vulnerabilities were removed or added between two update operations.  

The following sections outline how this is implemented.  

### Update Operations And Diffs

Two new libvuln.Driver objects are introduced to model an update operation and an diff between operations  

```
// Our diff terminology uses UpdateOpeartion A and UpdateOperation B as arguments.
// A is always the base and B is the update being applied over A.

// UpdateOperation is a unique update to the vulnstore by an Updater.
type UpdateOperation struct {
	ID          string
	Updater     string
	Fingerprint Fingerprint
	Date        time.Time
}

// UpdateDiff represents added or removed vulnerabilities between update operations
type UpdateDiff struct {
	A       UpdateOperation
	B       UpdateOperation
	Added   []*claircore.Vulnerability
	Removed []*claircore.Vulnerability
}
```

Database support is added in way of a new relation for `update_operation` and two new columns on the `vuln` relation.  

```
CREATE TABLE IF NOT EXISTS update_operation
(
    id			text PRIMARY KEY,
    updater		text,
    fingerprint text,
    date		timestamp with time zone
);
CREATE INDEX IF NOT EXISTS uo_updater_idx ON update_operation (updater);

CREATE TABLE IF NOT EXISTS vuln
(
    id                     BIGSERIAL PRIMARY KEY,
    uo_id                  text REFERENCES update_operation ON DELETE CASCADE,
    hash                   text,
    name                   text,
    description            text,
    links                  text,
    severity               text,
    package_name           text,
    package_version        text,
    package_kind           text,
    dist_id                text,
    dist_name              text,
    dist_version           text,
    dist_version_code_name text,
    dist_version_id        text,
    dist_arch              text,
    dist_cpe               text,
    dist_pretty_name       text,
    repo_name              text,
    repo_key               text,
    repo_uri               text,
    fixed_in_version       text,
    active				   boolean
);
CREATE INDEX IF NOT EXISTS vuln_lookup_idx on vuln (active, package_name, dist_version_code_name, dist_pretty_name, dist_name,
                                                    dist_version_id, dist_version, dist_arch, dist_cpe);
CREATE UNIQUE INDEX IF NOT EXISTS unique_vulnerability_id ON vuln (uo_id, hash);
`
```
Column `uo_id` references an owning `UpdateOperation` id and `hash` represents a hash of the vulnerability data.  
In the near future a `stable_id` can be identified for each security database and used in addition with the `hash` to identify "changed" vulnerabilities.  

On deletion of an `update_operation` all associated `vuln` entries are removed from the relation via CASCADE delete.

### Vulnstore Interface Refactor

The `vulnstore.Updater` interface is refactored to support `UpdateOperation` and `UpdateDiff` functionality. 

```
// Updater is an interface exporting the necessary methods
// for updating a vulnerability database
type Updater interface {
	// UpdateVulnerabilities creates a new UpdateOperation, inserts the provided vulnerabilities, and ensures vulnerabilities from previous updates
	// are not queried by clients.
	UpdateVulnerabilities(ctx context.Context, updater string, UOID string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) error
	// GetUpdateOperations returns a list of UpdateOperations in date descending order for the given updaters.
	// Returned map is keyed by Updater implementations unique names.
	// If updater slice is nil or empty all UpdateOperations are returned.
	GetUpdateOperations(ctx context.Context, updater []string) (map[string][]*driver.UpdateOperation, error)
	// DeleteUpdateOperations removes an UpdateOperation and the associated vulnerabilities from the vulnstore.
	DeleteUpdateOperations(ctx context.Context, UOID []string) error
	// GetUpdateOperationDiff returns the vulnerabilities added and removed when UpdaterOperation B is applied to UpdateOperation A.
	// Implementations decide if appling diffs between non-sequential updates is an error.
	GetUpdateOperationDiff(ctx context.Context, UOID_A, UOID_B string) (*driver.UpdateDiff, error)
}
```

### Libvuln Structure Refactor

The Libvuln struct implementing `libvuln` functionality grows exported methods to support retrieval and deletion of `UpdateOperation` and `UpdateDiff` models.

```
func (l *libvuln) GetUpdateOperations
func (l *libvuln) DeleteUpdateOperations
func (l *libvuln) GetUpdateOperationDiff
```

## Affected Manifests Report

On event of a notification the client must be informed which manifest hashes the added/removed vulnerability affects.  
In order to accomplish this we must provide an `AffectedManifestsReport` to the client.  
An `AffectedManifestsReport` will be the model delivered on notification event.  


The follow sections outline how this is implemented.  

### Manifest Index Relation

A new relation called "manifest_index" will be created.  
The relation will maintain a searchable index mapping package/distribution/repository data to the manifests which contain said data.  
A lookup on this relation should remain efficient.  

```
    --- ManifestIndex
	--- A searchable index mapping coalesced container contents to their manifest hash
	CREATE TABLE IF NOT EXISTS manifest_index (
		id BIGSERIAL PRIMARY KEY,
		package_id bigint REFERENCES package(id),
		dist_id bigint REFERENCES dist(id),
		repo_id bigint REFERENCES repo(id),
		manifest_hash text
	);
	CREATE UNIQUE INDEX IF NOT EXISTS manifest_index_unique_idx ON manifest_index (package_id, dist_id, repo_id, manifest_hash);
	CREATE INDEX IF NOT EXISTS manifest_index_lookup_idx ON manifest_index (package_id, dist_id, repo_id);
```

The relation simply maps package/distribution/repo ids to a manifest string allowing a manifest hash lookup via a single query.  

### IndexManifest State

A state will be added to the `indexer`'s state machine dubbed `IndexManifest`.  
This will be the final state of the state machine and will write rows to the `manifest_index` linking the **coalesced** container's content to a manifest hash string.  

### Affected Manifests Methods

Both `internal.indexer.Store` and `libindex` struct will grow methods for ingesting a `claircore.Vulnerability` and outputting any affected manifest hashes.  
The returned response will simply be a list of manifest hashes affected by the vulnerability.  
`libindex` methods may need to perform in-memory filtering of version strings to correctly report package vulnerability.  

## Notifier Service

While the main functionality for notification is implemented in `ClairCore` the driving application will be `ClairV4`'s notifier service.  
This service will be responsible for:
* Querying the `Matcher` to find new `UpdateOperations` and their `UpdateDiffs`.
* Querying the `Indexer` to retrieve a list of affected manifests.  
* Sending and bookeeping of notifications to registered clients.  

### Notification Delivery

Webhooks will be the preferred method of notification delivery.  
