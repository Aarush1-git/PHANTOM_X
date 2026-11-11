"""002_scope_safety_management

Revision ID: 002_scope_safety_management
Revises: 001_initial_schema
Create Date: 2026-11-10 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.models.base import GUID

revision: str = '002_scope_safety_management'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Application Scope Policies
    op.create_table(
        'application_scope_policies',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('target_domain', sa.String(length=255), nullable=False),
        sa.Column('base_url', sa.String(length=500), nullable=False),
        sa.Column('permitted_paths', sa.JSON(), nullable=False),
        sa.Column('excluded_paths', sa.JSON(), nullable=False),
        sa.Column('scope_status', sa.String(length=50), nullable=False, server_default='DRAFT'),
        sa.Column('authorization_status', sa.String(length=50), nullable=False, server_default='PENDING'),
        sa.Column('authorized_by', sa.String(length=255), nullable=True),
        sa.Column('authorizer_role', sa.String(length=100), nullable=True),
        sa.Column('authorization_notes', sa.Text(), nullable=True),
        sa.Column('valid_from', sa.DateTime(timezone=True), nullable=True),
        sa.Column('valid_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rate_limit_rps', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('max_concurrency', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('max_scan_duration_minutes', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('allowed_methods', sa.JSON(), nullable=False),
        sa.Column('restricted_endpoint_patterns', sa.JSON(), nullable=False),
        sa.Column('require_synthetic_auth', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('allow_destructive', sa.Boolean(), nullable=False, server_default='0'),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('application_id')
    )
    op.create_index('ix_scope_policies_org_id', 'application_scope_policies', ['organization_id'])
    op.create_index('ix_scope_policies_app_id', 'application_scope_policies', ['application_id'])
    op.create_index('ix_scope_policies_status', 'application_scope_policies', ['scope_status'])
    op.create_index('ix_scope_policies_auth_status', 'application_scope_policies', ['authorization_status'])

    # 2. Blocked Execution Logs
    op.create_table(
        'blocked_execution_logs',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=True),
        sa.Column('target_url', sa.String(length=1000), nullable=False),
        sa.Column('http_method', sa.String(length=20), nullable=False),
        sa.Column('violation_category', sa.String(length=100), nullable=False),
        sa.Column('blocked_reason', sa.String(length=1000), nullable=False),
        sa.Column('payload_sample', sa.Text(), nullable=True),
        sa.Column('source_agent', sa.String(length=100), nullable=True),
        sa.Column('client_ip', sa.String(length=50), nullable=True),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_blocked_exec_org_id', 'blocked_execution_logs', ['organization_id'])
    op.create_index('ix_blocked_exec_app_id', 'blocked_execution_logs', ['application_id'])
    op.create_index('ix_blocked_exec_violation', 'blocked_execution_logs', ['violation_category'])


def downgrade() -> None:
    op.drop_table('blocked_execution_logs')
    op.drop_table('application_scope_policies')
