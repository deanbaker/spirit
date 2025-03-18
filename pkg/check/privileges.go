package check

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/siddontang/loggers"
)

func init() {
	registerCheck("privileges", privilegesCheck, ScopePreflight)
}

// Check the privileges of the user running the migration.
// Ensure there is LOCK TABLES etc so we don't find out and get errors
// at cutover time.
func privilegesCheck(ctx context.Context, r Resources, logger loggers.Advanced) error {
	// This is a re-implementation of the gh-ost check
	// validateGrants() in gh-ost/go/logic/inspect.go

	logger.Infof("Checking privileges for schema: %s", r.Table.SchemaName)

	var foundAll, foundSuper, foundReplicationClient, foundReplicationSlave, foundDBAll, foundReload bool
	rows, err := r.DB.QueryContext(ctx, `SHOW GRANTS`) //nolint: execinquery
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var grant string
		if err := rows.Scan(&grant); err != nil {
			return err
		}
		// Debug output of each grant
		logger.Infof("Checking grant: %s", grant)

		if strings.Contains(grant, `GRANT ALL PRIVILEGES ON *.*`) {
			foundAll = true
		}
		if strings.Contains(grant, `SUPER`) && strings.Contains(grant, ` ON *.*`) {
			foundSuper = true
		}
		if strings.Contains(grant, `REPLICATION CLIENT`) && strings.Contains(grant, ` ON *.*`) {
			foundReplicationClient = true
		}
		if strings.Contains(grant, `REPLICATION SLAVE`) && strings.Contains(grant, ` ON *.*`) {
			foundReplicationSlave = true
		}
		if strings.Contains(grant, `RELOAD`) && strings.Contains(grant, ` ON *.*`) {
			foundReload = true
		}
		if strings.Contains(grant, fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.*", r.Table.SchemaName)) {
			foundDBAll = true
		}
		if strings.Contains(grant, fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.*", strings.Replace(r.Table.SchemaName, "_", "\\_", -1))) {
			foundDBAll = true
		}
		if stringContainsAll(grant, `ALTER`, `CREATE`, `DELETE`, `DROP`, `INDEX`, `INSERT`, `LOCK TABLES`, `SELECT`, `TRIGGER`, `UPDATE`, ` ON *.*`) {
			foundDBAll = true
		}
		if stringContainsAll(grant, `ALTER`, `CREATE`, `DELETE`, `DROP`, `INDEX`, `INSERT`, `LOCK TABLES`, `SELECT`, `TRIGGER`, `UPDATE`, fmt.Sprintf(" ON `%s`.*", r.Table.SchemaName)) {
			foundDBAll = true
		}
	}
	if rows.Err() != nil {
		return rows.Err()
	}

	// Debug output of privilege state
	logger.Infof("Privilege check results:")
	logger.Infof("- ALL PRIVILEGES: %v", foundAll)
	logger.Infof("- SUPER: %v", foundSuper)
	logger.Infof("- REPLICATION CLIENT: %v", foundReplicationClient)
	logger.Infof("- REPLICATION SLAVE: %v", foundReplicationSlave)
	logger.Infof("- DB ALL: %v", foundDBAll)
	logger.Infof("- RELOAD: %v", foundReload)

	if foundAll {
		logger.Info("Found ALL PRIVILEGES - check passing")
		return nil
	}
	if foundSuper && foundReplicationSlave && foundDBAll {
		logger.Info("Found SUPER + REPLICATION SLAVE + DB ALL - check passing")
		return nil
	}
	if foundReplicationClient && foundReplicationSlave && foundDBAll && foundReload {
		logger.Info("Found REPLICATION CLIENT + REPLICATION SLAVE + DB ALL + RELOAD - check passing")
		return nil
	}
	return errors.New("insufficient privileges to run a migration. Needed: SUPER|REPLICATION CLIENT, RELOAD, REPLICATION SLAVE and ALL on %s.*")
}

// stringContainsAll returns true if `s` contains all non empty given `substrings`
// The function returns `false` if no non-empty arguments are given.
func stringContainsAll(s string, substrings ...string) bool {
	nonEmptyStringsFound := false
	for _, substring := range substrings {
		if substring == "" {
			continue
		}
		if strings.Contains(s, substring) {
			nonEmptyStringsFound = true
		} else {
			// Immediate failure
			return false
		}
	}
	return nonEmptyStringsFound
}
