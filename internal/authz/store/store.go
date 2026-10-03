package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/authz/schema"
)

// Store handles persistent storage and snapshot consistency for Zanzibar relationships and schemas.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new Authz Store backed by PostgreSQL.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// CreateTenant creates a new tenant record with revision 0 if it doesn't already exist.
func (s *Store) CreateTenant(ctx context.Context, tenantID string) error {
	if !ValidateID(tenantID, false) {
		return fmt.Errorf("%w: invalid tenant id %q", ErrInvalidIdentifier, tenantID)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO authz_tenants (tenant_id, current_rev)
		VALUES ($1, 0)
		ON CONFLICT (tenant_id) DO NOTHING
	`, tenantID)
	return err
}

// GetTenantRevision returns the current revision for the tenant.
func (s *Store) GetTenantRevision(ctx context.Context, tenantID string) (int64, error) {
	if !ValidateID(tenantID, false) {
		return 0, fmt.Errorf("%w: invalid tenant id %q", ErrInvalidIdentifier, tenantID)
	}

	var rev int64
	err := s.pool.QueryRow(ctx, `
		SELECT current_rev FROM authz_tenants WHERE tenant_id = $1
	`, tenantID).Scan(&rev)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrTenantNotFound
		}
		return 0, err
	}
	return rev, nil
}

// SaveSchema validates and stores a new schema version, atomically bumping the tenant revision.
func (s *Store) SaveSchema(ctx context.Context, tenantID string, version int, definition string, parsed *schema.Schema) (int64, error) {
	if !ValidateID(tenantID, false) {
		return 0, fmt.Errorf("%w: invalid tenant id %q", ErrInvalidIdentifier, tenantID)
	}
	if version <= 0 {
		return 0, errors.New("schema version must be positive")
	}

	parsedJSON, err := json.Marshal(parsed)
	if err != nil {
		return 0, fmt.Errorf("failed to serialize compiled schema: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Ensure tenant row exists
	_, err = tx.Exec(ctx, `
		INSERT INTO authz_tenants (tenant_id, current_rev)
		VALUES ($1, 0)
		ON CONFLICT (tenant_id) DO NOTHING
	`, tenantID)
	if err != nil {
		return 0, err
	}

	// Row lock tenant and increment revision
	var newRev int64
	err = tx.QueryRow(ctx, `
		UPDATE authz_tenants
		SET current_rev = current_rev + 1
		WHERE tenant_id = $1
		RETURNING current_rev
	`, tenantID).Scan(&newRev)
	if err != nil {
		return 0, err
	}

	// Insert schema
	_, err = tx.Exec(ctx, `
		INSERT INTO authz_schemas (tenant_id, version, definition, parsed, created_rev)
		VALUES ($1, $2, $3, $4, $5)
	`, tenantID, version, definition, parsedJSON, newRev)
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}

	return newRev, nil
}

// GetLatestSchema retrieves the newest compiled schema for a tenant.
func (s *Store) GetLatestSchema(ctx context.Context, tenantID string) (*schema.Schema, int, error) {
	if !ValidateID(tenantID, false) {
		return nil, 0, fmt.Errorf("%w: invalid tenant id %q", ErrInvalidIdentifier, tenantID)
	}

	var version int
	var parsedJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT version, parsed
		FROM authz_schemas
		WHERE tenant_id = $1
		ORDER BY version DESC
		LIMIT 1
	`, tenantID).Scan(&version, &parsedJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, 0, ErrNoSchema
		}
		return nil, 0, err
	}

	var sch schema.Schema
	if err := json.Unmarshal(parsedJSON, &sch); err != nil {
		return nil, 0, fmt.Errorf("failed to deserialize schema: %w", err)
	}

	return &sch, version, nil
}

// GetLatestSchemaVersion returns the newest schema version number for a tenant.
func (s *Store) GetLatestSchemaVersion(ctx context.Context, tenantID string) (int, error) {
	if !ValidateID(tenantID, false) {
		return 0, fmt.Errorf("%w: invalid tenant id %q", ErrInvalidIdentifier, tenantID)
	}

	var version int
	err := s.pool.QueryRow(ctx, `
		SELECT version
		FROM authz_schemas
		WHERE tenant_id = $1
		ORDER BY version DESC
		LIMIT 1
	`, tenantID).Scan(&version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNoSchema
		}
		return 0, err
	}
	return version, nil
}

// GetSchemaByVersion returns the compiled schema for a specific version.
func (s *Store) GetSchemaByVersion(ctx context.Context, tenantID string, version int) (*schema.Schema, error) {
	if !ValidateID(tenantID, false) {
		return nil, fmt.Errorf("%w: invalid tenant id %q", ErrInvalidIdentifier, tenantID)
	}

	var parsedJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT parsed
		FROM authz_schemas
		WHERE tenant_id = $1 AND version = $2
	`, tenantID, version).Scan(&parsedJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoSchema
		}
		return nil, err
	}

	var sch schema.Schema
	if err := json.Unmarshal(parsedJSON, &sch); err != nil {
		return nil, fmt.Errorf("failed to deserialize schema: %w", err)
	}

	return &sch, nil
}

// WriteRelationships executes a batch of relationship writes atomically in ONE transaction.
func (s *Store) WriteRelationships(ctx context.Context, tenantID string, ops []TupleOperation) (int64, error) {
	if !ValidateID(tenantID, false) {
		return 0, fmt.Errorf("%w: invalid tenant id %q", ErrInvalidIdentifier, tenantID)
	}

	if len(ops) == 0 {
		return s.GetTenantRevision(ctx, tenantID)
	}

	// Pre-validate all tuple shapes
	for i, op := range ops {
		op.Tuple.TenantID = tenantID
		if err := op.Tuple.Validate(); err != nil {
			return 0, fmt.Errorf("batch operation %d: %w", i, err)
		}
		if op.Op != OpTouch && op.Op != OpCreate && op.Op != OpDelete {
			return 0, fmt.Errorf("batch operation %d: invalid op %q (must be touch, create, or delete)", i, op.Op)
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Lock tenant row and bump revision
	var newRev int64
	err = tx.QueryRow(ctx, `
		UPDATE authz_tenants
		SET current_rev = current_rev + 1
		WHERE tenant_id = $1
		RETURNING current_rev
	`, tenantID).Scan(&newRev)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrTenantNotFound
		}
		return 0, err
	}

	// 2. Load latest schema inside the transaction
	var parsedJSON []byte
	err = tx.QueryRow(ctx, `
		SELECT parsed
		FROM authz_schemas
		WHERE tenant_id = $1
		ORDER BY version DESC
		LIMIT 1
	`, tenantID).Scan(&parsedJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNoSchema
		}
		return 0, err
	}

	var sch schema.Schema
	if err := json.Unmarshal(parsedJSON, &sch); err != nil {
		return 0, fmt.Errorf("failed to deserialize schema: %w", err)
	}

	// 3. Validate every tuple against the schema
	for i, op := range ops {
		if err := ValidateTupleAgainstSchema(&sch, &op.Tuple); err != nil {
			return 0, fmt.Errorf("batch operation %d: %w", i, err)
		}
	}

	// 4. Execute operations sequentially in transaction
	changelogSeq := 0
	for _, op := range ops {
		t := op.Tuple
		t.TenantID = tenantID

		switch op.Op {
		case OpCreate:
			// Must not already exist live
			var existingID string
			checkErr := tx.QueryRow(ctx, `
				SELECT object_id
				FROM authz_tuples
				WHERE tenant_id = $1
				  AND object_type = $2
				  AND object_id = $3
				  AND relation = $4
				  AND subject_type = $5
				  AND subject_id = $6
				  AND subject_relation = $7
				  AND deleted_rev IS NULL
				LIMIT 1
			`, tenantID, t.ObjectType, t.ObjectID, t.Relation, t.SubjectType, t.SubjectID, t.SubjectRelation).Scan(&existingID)

			if checkErr == nil {
				return 0, fmt.Errorf("%w: tuple %s is already live", ErrTupleAlreadyExists, t.String())
			}
			if !errors.Is(checkErr, pgx.ErrNoRows) {
				return 0, checkErr
			}

			// Insert new live tuple
			_, err = tx.Exec(ctx, `
				INSERT INTO authz_tuples (
					tenant_id, object_type, object_id, relation,
					subject_type, subject_id, subject_relation, created_rev
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			`, tenantID, t.ObjectType, t.ObjectID, t.Relation, t.SubjectType, t.SubjectID, t.SubjectRelation, newRev)
			if err != nil {
				return 0, err
			}

			changelogSeq++
			_, err = tx.Exec(ctx, `
				INSERT INTO authz_changelog (tenant_id, rev, seq, op, tuple_text)
				VALUES ($1, $2, $3, $4, $5)
			`, tenantID, newRev, changelogSeq, OpCreate, t.String())
			if err != nil {
				return 0, err
			}

		case OpTouch:
			// If already live, it's a no-op
			var existingID string
			checkErr := tx.QueryRow(ctx, `
				SELECT object_id
				FROM authz_tuples
				WHERE tenant_id = $1
				  AND object_type = $2
				  AND object_id = $3
				  AND relation = $4
				  AND subject_type = $5
				  AND subject_id = $6
				  AND subject_relation = $7
				  AND deleted_rev IS NULL
				LIMIT 1
			`, tenantID, t.ObjectType, t.ObjectID, t.Relation, t.SubjectType, t.SubjectID, t.SubjectRelation).Scan(&existingID)

			if checkErr != nil && !errors.Is(checkErr, pgx.ErrNoRows) {
				return 0, checkErr
			}

			if errors.Is(checkErr, pgx.ErrNoRows) {
				// Insert live tuple
				_, err = tx.Exec(ctx, `
					INSERT INTO authz_tuples (
						tenant_id, object_type, object_id, relation,
						subject_type, subject_id, subject_relation, created_rev
					) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
				`, tenantID, t.ObjectType, t.ObjectID, t.Relation, t.SubjectType, t.SubjectID, t.SubjectRelation, newRev)
				if err != nil {
					return 0, err
				}
			}

			changelogSeq++
			_, err = tx.Exec(ctx, `
				INSERT INTO authz_changelog (tenant_id, rev, seq, op, tuple_text)
				VALUES ($1, $2, $3, $4, $5)
			`, tenantID, newRev, changelogSeq, OpTouch, t.String())
			if err != nil {
				return 0, err
			}

		case OpDelete:
			// Soft-delete matching live row
			tag, err := tx.Exec(ctx, `
				UPDATE authz_tuples
				SET deleted_rev = $8
				WHERE tenant_id = $1
				  AND object_type = $2
				  AND object_id = $3
				  AND relation = $4
				  AND subject_type = $5
				  AND subject_id = $6
				  AND subject_relation = $7
				  AND deleted_rev IS NULL
			`, tenantID, t.ObjectType, t.ObjectID, t.Relation, t.SubjectType, t.SubjectID, t.SubjectRelation, newRev)
			if err != nil {
				return 0, err
			}

			// If row existed and was soft-deleted, or if it didn't exist (idempotent), record changelog
			if tag.RowsAffected() > 0 {
				changelogSeq++
				_, err = tx.Exec(ctx, `
					INSERT INTO authz_changelog (tenant_id, rev, seq, op, tuple_text)
					VALUES ($1, $2, $3, $4, $5)
				`, tenantID, newRev, changelogSeq, OpDelete, t.String())
				if err != nil {
					return 0, err
				}
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}

	return newRev, nil
}

// ReadTuples performs snapshot reads at the given revision.
func (s *Store) ReadTuples(ctx context.Context, tenantID string, filter TupleFilter, revision int64) ([]Tuple, error) {
	if !ValidateID(tenantID, false) {
		return nil, fmt.Errorf("%w: invalid tenant id %q", ErrInvalidIdentifier, tenantID)
	}

	var sb strings.Builder
	sb.WriteString(`
		SELECT tenant_id, object_type, object_id, relation,
		       subject_type, subject_id, subject_relation, created_rev, deleted_rev
		FROM authz_tuples
		WHERE tenant_id = $1
		  AND created_rev <= $2
		  AND (deleted_rev IS NULL OR deleted_rev > $2)
	`)

	args := []any{tenantID, revision}
	argIdx := 3

	if filter.ObjectType != "" {
		if !ValidateTypeOrRelation(filter.ObjectType) {
			return nil, fmt.Errorf("%w: invalid object type %q", ErrInvalidIdentifier, filter.ObjectType)
		}
		sb.WriteString(" AND object_type = $" + strconv.Itoa(argIdx))
		args = append(args, filter.ObjectType)
		argIdx++
	}

	if filter.ObjectID != "" {
		if !ValidateID(filter.ObjectID, false) {
			return nil, fmt.Errorf("%w: invalid object id %q", ErrInvalidIdentifier, filter.ObjectID)
		}
		sb.WriteString(" AND object_id = $" + strconv.Itoa(argIdx))
		args = append(args, filter.ObjectID)
		argIdx++
	}

	if filter.Relation != "" {
		if !ValidateTypeOrRelation(filter.Relation) {
			return nil, fmt.Errorf("%w: invalid relation %q", ErrInvalidIdentifier, filter.Relation)
		}
		sb.WriteString(" AND relation = $" + strconv.Itoa(argIdx))
		args = append(args, filter.Relation)
		argIdx++
	}

	if filter.SubjectType != "" {
		if !ValidateTypeOrRelation(filter.SubjectType) {
			return nil, fmt.Errorf("%w: invalid subject type %q", ErrInvalidIdentifier, filter.SubjectType)
		}
		sb.WriteString(" AND subject_type = $" + strconv.Itoa(argIdx))
		args = append(args, filter.SubjectType)
		argIdx++
	}

	if filter.SubjectID != "" {
		if !ValidateID(filter.SubjectID, true) {
			return nil, fmt.Errorf("%w: invalid subject id %q", ErrInvalidIdentifier, filter.SubjectID)
		}
		sb.WriteString(" AND subject_id = $" + strconv.Itoa(argIdx))
		args = append(args, filter.SubjectID)
		argIdx++
	}

	if filter.SubjectRelation != nil {
		if *filter.SubjectRelation != "" && !ValidateTypeOrRelation(*filter.SubjectRelation) {
			return nil, fmt.Errorf("%w: invalid subject relation %q", ErrInvalidIdentifier, *filter.SubjectRelation)
		}
		sb.WriteString(" AND subject_relation = $" + strconv.Itoa(argIdx))
		args = append(args, *filter.SubjectRelation)
	}

	sb.WriteString(" ORDER BY object_type, object_id, relation, subject_type, subject_id, subject_relation")

	if filter.Limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", filter.Limit))
	}

	rows, err := s.pool.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []Tuple
	for rows.Next() {
		var t Tuple
		err := rows.Scan(
			&t.TenantID,
			&t.ObjectType,
			&t.ObjectID,
			&t.Relation,
			&t.SubjectType,
			&t.SubjectID,
			&t.SubjectRelation,
			&t.CreatedRev,
			&t.DeletedRev,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, t)
	}

	return result, rows.Err()
}

// ValidateTupleAgainstSchema verifies that a tuple adheres to the tenant's current schema.
func ValidateTupleAgainstSchema(sch *schema.Schema, t *Tuple) error {
	typeDef, ok := sch.Types[t.ObjectType]
	if !ok {
		return fmt.Errorf("%w: unknown object type %q", ErrSchemaValidation, t.ObjectType)
	}

	relDef, ok := typeDef.Relations[t.Relation]
	if !ok {
		return fmt.Errorf("%w: unknown relation %q on type %q", ErrSchemaValidation, t.Relation, t.ObjectType)
	}

	matchFound := false
	for _, rule := range relDef.SubjectTypes {
		if rule.Type != t.SubjectType {
			continue
		}
		if t.SubjectID == "*" {
			if rule.IsWildcard {
				matchFound = true
				break
			}
			continue
		}
		if t.SubjectRelation != "" {
			if rule.Relation == t.SubjectRelation {
				matchFound = true
				break
			}
			continue
		}
		// Direct subject
		if !rule.IsWildcard && rule.Relation == "" {
			matchFound = true
			break
		}
	}

	if !matchFound {
		return fmt.Errorf("%w: subject %s is not an allowed subject type for %s#%s",
			ErrSchemaValidation, t.SubjectType+":"+t.SubjectID, t.ObjectType, t.Relation)
	}

	// If userset subject relation, verify relation exists on subject type
	if t.SubjectRelation != "" {
		subjTypeDef, ok := sch.Types[t.SubjectType]
		if !ok {
			return fmt.Errorf("%w: unknown subject type %q", ErrSchemaValidation, t.SubjectType)
		}
		if _, ok := subjTypeDef.Relations[t.SubjectRelation]; !ok {
			return fmt.Errorf("%w: unknown relation %q on subject type %q", ErrSchemaValidation, t.SubjectRelation, t.SubjectType)
		}
	}

	return nil
}
