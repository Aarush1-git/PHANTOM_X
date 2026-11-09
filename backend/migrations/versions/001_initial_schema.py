"""001_initial_schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-11-09 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.models.base import GUID

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Organizations
    op.create_table(
        'organizations',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organizations_slug', 'organizations', ['slug'], unique=True)

    # 2. Users
    op.create_table(
        'users',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=100), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_users_organization_id', 'users', ['organization_id'])

    # 3. Applications
    op.create_table(
        'applications',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=1000), nullable=True),
        sa.Column('target_url', sa.String(length=500), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False, default=0.0),
        sa.Column('status', sa.String(length=50), nullable=False, default='ACTIVE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_applications_name', 'applications', ['name'])
    op.create_index('ix_applications_organization_id', 'applications', ['organization_id'])

    # 4. Application Environments
    op.create_table(
        'application_environments',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('base_url', sa.String(length=500), nullable=False),
        sa.Column('env_type', sa.String(length=50), nullable=False, default='staging'),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_application_environments_application_id', 'application_environments', ['application_id'])

    # 5. Application Roles
    op.create_table(
        'application_roles',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=500), nullable=True),
        sa.Column('permissions', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_application_roles_application_id', 'application_roles', ['application_id'])

    # 6. Resource Relationships
    op.create_table(
        'resource_relationships',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('source_resource', sa.String(length=100), nullable=False),
        sa.Column('target_resource', sa.String(length=100), nullable=False),
        sa.Column('relationship_type', sa.String(length=50), nullable=False),
        sa.Column('is_bidirectional', sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_resource_relationships_application_id', 'resource_relationships', ['application_id'])

    # 7. Scan Configurations
    op.create_table(
        'scan_configurations',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('mode', sa.String(length=50), nullable=False),
        sa.Column('max_depth', sa.Integer(), nullable=False, default=3),
        sa.Column('concurrency', sa.Integer(), nullable=False, default=3),
        sa.Column('rate_limit_rps', sa.Integer(), nullable=False, default=10),
        sa.Column('test_categories', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_configurations_organization_id', 'scan_configurations', ['organization_id'])

    # 8. Scans
    op.create_table(
        'scans',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('configuration_id', GUID(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('progress', sa.Float(), nullable=False, default=0.0),
        sa.Column('findings_count', sa.Integer(), nullable=False, default=0),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('notes', sa.String(length=1000), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['configuration_id'], ['scan_configurations.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scans_application_id', 'scans', ['application_id'])
    op.create_index('ix_scans_organization_id', 'scans', ['organization_id'])
    op.create_index('ix_scans_status', 'scans', ['status'])

    # 9. Discovered Endpoints
    op.create_table(
        'discovered_endpoints',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('path', sa.String(length=500), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('auth_required', sa.Boolean(), nullable=False, default=True),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('response_codes', sa.JSON(), nullable=False),
        sa.Column('risk_level', sa.String(length=50), nullable=False),
        sa.Column('raw_metadata', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_discovered_endpoints_application_id', 'discovered_endpoints', ['application_id'])
    op.create_index('ix_discovered_endpoints_path', 'discovered_endpoints', ['path'])

    # 10. Attack Plans
    op.create_table(
        'attack_plans',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('scan_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, default='DRAFT'),
        sa.Column('scenarios', sa.JSON(), nullable=False),
        sa.Column('approved_by', GUID(), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['approved_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_attack_plans_application_id', 'attack_plans', ['application_id'])
    op.create_index('ix_attack_plans_scan_id', 'attack_plans', ['scan_id'])

    # 11. Security Tests
    op.create_table(
        'security_tests',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('plan_id', GUID(), nullable=False),
        sa.Column('endpoint_id', GUID(), nullable=False),
        sa.Column('test_category', sa.String(length=100), nullable=False),
        sa.Column('test_parameters', sa.JSON(), nullable=False),
        sa.Column('safety_classification', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('result_summary', sa.String(length=1000), nullable=True),
        sa.ForeignKeyConstraint(['endpoint_id'], ['discovered_endpoints.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['plan_id'], ['attack_plans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_security_tests_endpoint_id', 'security_tests', ['endpoint_id'])
    op.create_index('ix_security_tests_plan_id', 'security_tests', ['plan_id'])
    op.create_index('ix_security_tests_status', 'security_tests', ['status'])

    # 12. Vulnerabilities
    op.create_table(
        'vulnerabilities',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('scan_id', GUID(), nullable=True),
        sa.Column('test_id', GUID(), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('endpoint', sa.String(length=500), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, default=0.8),
        sa.Column('recommendation', sa.Text(), nullable=False),
        sa.Column('cwe_id', sa.String(length=50), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['test_id'], ['security_tests.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_vulnerabilities_application_id', 'vulnerabilities', ['application_id'])
    op.create_index('ix_vulnerabilities_organization_id', 'vulnerabilities', ['organization_id'])
    op.create_index('ix_vulnerabilities_scan_id', 'vulnerabilities', ['scan_id'])
    op.create_index('ix_vulnerabilities_severity', 'vulnerabilities', ['severity'])
    op.create_index('ix_vulnerabilities_status', 'vulnerabilities', ['status'])
    op.create_index('ix_vulnerabilities_title', 'vulnerabilities', ['title'])

    # 13. Evidences
    op.create_table(
        'evidences',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('vulnerability_id', GUID(), nullable=True),
        sa.Column('test_id', GUID(), nullable=True),
        sa.Column('request_dump', sa.Text(), nullable=False),
        sa.Column('response_dump', sa.Text(), nullable=False),
        sa.Column('proof_data', sa.JSON(), nullable=False),
        sa.Column('screenshot_url', sa.String(length=500), nullable=True),
        sa.Column('har_entry', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['test_id'], ['security_tests.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_evidences_vulnerability_id', 'evidences', ['vulnerability_id'])

    # 14. Attack Chains
    op.create_table(
        'attack_chains',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('scan_id', GUID(), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=1000), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('nodes', sa.JSON(), nullable=False),
        sa.Column('edges', sa.JSON(), nullable=False),
        sa.Column('is_verified', sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_attack_chains_application_id', 'attack_chains', ['application_id'])

    # 15. Regression Tests
    op.create_table(
        'regression_tests',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('vulnerability_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('previous_test_id', GUID(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('result_summary', sa.String(length=1000), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['previous_test_id'], ['security_tests.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_regression_tests_application_id', 'regression_tests', ['application_id'])
    op.create_index('ix_regression_tests_vulnerability_id', 'regression_tests', ['vulnerability_id'])

    # 16. Scan Comparisons
    op.create_table(
        'scan_comparisons',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('base_scan_id', GUID(), nullable=False),
        sa.Column('target_scan_id', GUID(), nullable=False),
        sa.Column('new_vulnerabilities', sa.JSON(), nullable=False),
        sa.Column('resolved_vulnerabilities', sa.JSON(), nullable=False),
        sa.Column('unchanged_vulnerabilities', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['base_scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_comparisons_base_scan_id', 'scan_comparisons', ['base_scan_id'])
    op.create_index('ix_scan_comparisons_target_scan_id', 'scan_comparisons', ['target_scan_id'])

    # 17. Audit Logs
    op.create_table(
        'audit_logs',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('user_id', GUID(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('target_type', sa.String(length=100), nullable=False),
        sa.Column('target_id', sa.String(length=100), nullable=True),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('ip_address', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_organization_id', 'audit_logs', ['organization_id'])

    # 18. Scope Permissions
    op.create_table(
        'scope_permissions',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('host_pattern', sa.String(length=255), nullable=False),
        sa.Column('allowed_methods', sa.JSON(), nullable=False),
        sa.Column('rate_limit_rps', sa.Integer(), nullable=False, default=10),
        sa.Column('is_destructive_allowed', sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scope_permissions_application_id', 'scope_permissions', ['application_id'])
    op.create_index('ix_scope_permissions_organization_id', 'scope_permissions', ['organization_id'])


def downgrade() -> None:
    op.drop_table('scope_permissions')
    op.drop_table('audit_logs')
    op.drop_table('scan_comparisons')
    op.drop_table('regression_tests')
    op.drop_table('attack_chains')
    op.drop_table('evidences')
    op.drop_table('vulnerabilities')
    op.drop_table('security_tests')
    op.drop_table('attack_plans')
    op.drop_table('discovered_endpoints')
    op.drop_table('scans')
    op.drop_table('scan_configurations')
    op.drop_table('resource_relationships')
    op.drop_table('application_roles')
    op.drop_table('application_environments')
    op.drop_table('applications')
    op.drop_table('users')
    op.drop_table('organizations')

