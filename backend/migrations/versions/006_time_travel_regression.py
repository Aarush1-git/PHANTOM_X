"""006_time_travel_regression

Revision ID: 006_time_travel_regression
Revises: 005_vulnerability_reports_retention
Create Date: 2026-11-11 11:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.models.base import GUID

revision: str = '006_time_travel_regression'
down_revision: Union[str, None] = '005_vulnerability_reports_retention'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create security_baselines table
    op.create_table(
        'security_baselines',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('source_scan_id', GUID(), nullable=True),
        sa.Column('verification_scan_id', GUID(), nullable=True),
        sa.Column('original_vulnerability_id', GUID(), nullable=True),
        sa.Column('vulnerability_fingerprint', sa.String(length=255), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=True),
        sa.Column('cwe_id', sa.String(length=50), nullable=True),
        sa.Column('endpoint', sa.String(length=500), nullable=False),
        sa.Column('http_method', sa.String(length=20), server_default='GET', nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='VERIFIED', nullable=False),
        sa.Column('verification_timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verification_status', sa.String(length=50), server_default='VERIFIED', nullable=False),
        sa.Column('verification_reason', sa.String(length=500), nullable=True),
        sa.Column('evidence_references', sa.JSON(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('is_retired', sa.Boolean(), server_default=sa.text('0'), nullable=False),
        sa.Column('retired_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retired_reason', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['source_scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['verification_scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['original_vulnerability_id'], ['vulnerabilities.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('application_id', 'vulnerability_fingerprint', name='uq_baseline_app_fingerprint')
    )
    op.create_index('ix_security_baselines_organization_id', 'security_baselines', ['organization_id'])
    op.create_index('ix_security_baselines_application_id', 'security_baselines', ['application_id'])
    op.create_index('ix_security_baselines_vulnerability_fingerprint', 'security_baselines', ['vulnerability_fingerprint'])

    # Create regression_records table
    op.create_table(
        'regression_records',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('baseline_id', GUID(), nullable=False),
        sa.Column('scan_id', GUID(), nullable=False),
        sa.Column('reappeared_vulnerability_id', GUID(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('match_quality', sa.String(length=50), nullable=False),
        sa.Column('confidence_score', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('original_severity', sa.String(length=50), nullable=False),
        sa.Column('new_severity', sa.String(length=50), nullable=True),
        sa.Column('severity_change', sa.String(length=50), nullable=True),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('evidence_references', sa.JSON(), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=False),
        sa.Column('remediation_notes', sa.Text(), nullable=True),
        sa.Column('is_resolved', sa.Boolean(), server_default=sa.text('0'), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['baseline_id'], ['security_baselines.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['reappeared_vulnerability_id'], ['vulnerabilities.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('baseline_id', 'scan_id', name='uq_baseline_scan_evaluation')
    )
    op.create_index('ix_regression_records_organization_id', 'regression_records', ['organization_id'])
    op.create_index('ix_regression_records_application_id', 'regression_records', ['application_id'])
    op.create_index('ix_regression_records_baseline_id', 'regression_records', ['baseline_id'])
    op.create_index('ix_regression_records_scan_id', 'regression_records', ['scan_id'])


def downgrade() -> None:
    op.drop_table('regression_records')
    op.drop_table('security_baselines')

