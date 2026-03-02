# Database Directory

## Overview

This directory contains the database schema and initialization scripts for the Scrutinise Workflow Management System. The application uses PostgreSQL as the database backend with comprehensive schema management.

## Files

### `init.sql`
**Purpose**: Complete PostgreSQL database schema initialization script
**Usage**: Automatically executed during Docker Compose startup
**Contains**:
- All table definitions with constraints and indexes
- Foreign key relationships
- Initial data and default admin user
- Trigger functions and stored procedures
- Performance optimization indexes

### Rules Table & Excel Loader
The schema includes a `rules` table (with a unique index on `(category, rule)`) designed to hold configurable rule metadata. You can populate it via the Admin UI using an Excel file.

Supported Excel columns (case-insensitive; flexible names accepted):
- Category
- Rule (or Rule Name / Name)
- Trigger Condition (or Trigger / Condition)
- Score Impact (or Impact / Score)
- Tag(s) (or Tags / Rule Tags)
- Escalation Outcome (or Outcome / Severity Outcome)
- Description (or Plain Description / Explanation)

Admin UI import steps:
1. Ensure the database is initialized with `init.sql`.
2. Start the app and log in as an admin.
3. Navigate to Configuration → Rules & Settings.
4. In the “Rules table (advanced)” card:
  - Optionally click “Wipe rules” to clear existing entries.
  - Upload your Excel and choose “Reload from Excel”.
5. The app will upsert rows based on `(category, rule)`.

Notes:
- If you prefer CLI-based loading, see `app/seed_rules.py` for a reference implementation of the Excel-to-DB loader. It demonstrates header normalization and upsert semantics and can be adapted to your runtime database if needed.

## Database Schema Overview

### Core Tables

#### User Management
- **`users`** - User accounts, roles, authentication data, team assignments
- **`password_resets`** - Secure password reset tokens with TTL
- **`permissions`** - Role-based access control definitions
- **`field_visibility`** - Dynamic UI field visibility controls

#### Workflow Management
- **`reviews`** - Central workflow table with multi-level review columns
  - Task assignment fields (`l1_assigned_to`, `l2_assigned_to`, `l3_assigned_to`)
  - Level-specific outcomes and rationale
  - SME referral workflow integration
  - QC workflow tracking
  - Comprehensive audit timestamps

#### Quality Control
- **`reviewer_accreditation`** - QC accreditation status and certification levels
- **`reviewer_accreditation_log`** - Complete audit trail for accreditation changes
- **`sampling_rates`** - Configurable QC sampling rules by reviewer/level
- **`escalation_log`** - Task escalation audit trail with full history

#### Reporting & Planning
- **`forecast_planning`** - Capacity planning and workload forecasting
- **`settings`** - Application-wide configuration parameters
- **`matches`** - Task scoring and allocation tracking

### Key Features

#### Database Abstraction
- **Optimized PostgreSQL Integration**: Tuned for PostgreSQL performance and features
- **Connection Management**: Pooling and transaction handling
- **Prepared Statements**: SQL injection protection
- **Error Handling**: Graceful degradation and logging

#### Data Integrity
- **Foreign Key Constraints**: Referential integrity between all related tables
- **Check Constraints**: Data validation at database level
- **Unique Constraints**: Business rule enforcement
- **Indexes**: Query performance optimization

#### Security & Audit
- **Timestamp Tracking**: Created/updated timestamps on all major tables
- **Password Security**: bcrypt hashing with salt
- **Session Management**: Secure session token handling
- **Audit Logging**: Complete change history for critical operations

## Database Operations

### Automatic Initialization
The database is automatically initialized during Docker Compose startup:

```bash
# Start with fresh database
docker compose up -d

# Monitor initialization
docker compose logs postgres --follow
```

### Manual Operations

#### Connect to Database
```bash
# Via Docker
docker compose exec postgres psql -U scrutinise_user -d scrutinise_workflow

# Direct connection (if PostgreSQL running locally)
psql -h localhost -U scrutinise_user -d scrutinise_workflow
```

#### Schema Inspection
```sql
-- List all tables
\dt

-- Describe table structure
\d users

-- Show indexes
\di

-- Show foreign keys
\d+ reviews
```

#### Backup & Restore
```bash
# Backup database
docker compose exec postgres pg_dump -U scrutinise_user scrutinise_workflow > backup.sql

# Restore database
docker compose exec -T postgres psql -U scrutinise_user -d scrutinise_workflow < backup.sql
```

### Database Migration

#### Schema Updates
The application includes schema migration capabilities:

1. **Development**: Test changes in local environment
2. **Migration Script**: Create incremental update script
3. **Backup**: Always backup before schema changes
4. **Apply**: Run migration during maintenance window
5. **Verify**: Confirm data integrity post-migration

## Performance Considerations

### Indexes
The schema includes optimized indexes for:
- Primary key lookups
- Foreign key relationships
- Frequently queried columns
- Composite queries (multi-column indexes)

### Query Optimization
- **Prepared Statements**: Reuse execution plans
- **Connection Pooling**: Reduce connection overhead
- **Transaction Management**: Minimize lock duration
- **Batch Operations**: Bulk inserts/updates where possible

### Monitoring
```sql
-- Check table sizes
SELECT schemaname, tablename, 
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Monitor active connections
SELECT datname, numbackends, xact_commit, xact_rollback 
FROM pg_stat_database 
WHERE datname = 'scrutinise_workflow';

-- Check slow queries (requires pg_stat_statements extension)
SELECT query, mean_exec_time, calls 
FROM pg_stat_statements 
ORDER BY mean_exec_time DESC 
LIMIT 10;
```

## Troubleshooting

### Common Issues

#### Connection Problems
```bash
# Check PostgreSQL is running
docker compose ps postgres

# Test connectivity
docker compose exec postgres pg_isready -U scrutinise_user

# Check logs for errors
docker compose logs postgres --follow
```

#### Schema Issues
```bash
# Verify tables exist
docker compose exec postgres psql -U scrutinise_user -d scrutinise_workflow -c "\dt"

# Recreate database (DESTROYS ALL DATA)
docker compose down -v
docker compose up -d
```

#### Performance Issues
```sql
-- Check for missing indexes
SELECT schemaname, tablename, attname, n_distinct, correlation 
FROM pg_stats 
WHERE schemaname = 'public' 
AND n_distinct > 100;

-- Analyze table statistics
ANALYZE;

-- Update query planner statistics
VACUUM ANALYZE;
```

## Security Notes

- **Default Credentials**: Change default PostgreSQL password in production
- **Network Access**: Restrict database access to application servers only
- **Encryption**: Use SSL/TLS for database connections in production
- **Backups**: Encrypt backup files containing sensitive data
- **Access Control**: Limit database user privileges to minimum required

## Related Documentation

- **[Main README](../README.md)** - Complete application documentation
- **[Docker Setup](../dockerfile/README.md)** - Container configuration
- **[Testing](../tests/README.md)** - Database testing procedures
- **[Maintenance](../maintenance/README.md)** - Database maintenance scripts