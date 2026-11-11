"""008_remediation_recommendations

Revision ID: 008_remediation_recommendations
Revises: 007_playground_sessions
Create Date: 2026-11-11 14:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.models.base import GUID

revision: str = '008_remediation_recommendations'
down_revision: Union[str, None] = '007_playground_sessions'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'remediation_recommendations',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('vulnerability_id', GUID(), nullable=False),
        sa.Column('scan_id', GUID(), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=False),
        sa.Column('cwe_id', sa.String(length=50), nullable=True),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('calculated_priority', sa.String(length=50), server_default='MEDIUM', nullable=False),
        sa.Column('risk_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('status', sa.String(length=50), server_default='GENERATED', nullable=False),
        sa.Column('endpoint', sa.String(length=500), nullable=True),
        sa.Column('http_method', sa.String(length=20), server_default='GET', nullable=True),
        sa.Column('priority_rationale', sa.JSON(), nullable=False),
        sa.Column('why_it_matters', sa.Text(), nullable=False),
        sa.Column('potential_business_impact', sa.Text(), nullable=False),
        sa.Column('remediation_steps', sa.JSON(), nullable=False),
        sa.Column('suggested_fix_snippet', sa.Text(), nullable=True),
        sa.Column('validation_steps', sa.JSON(), nullable=False),
        sa.Column('suggested_playground_scenario_id', sa.String(length=100), nullable=True),
        sa.Column('estimated_effort', sa.String(length=50), server_default='MEDIUM', nullable=True),
        sa.Column('missing_information_notes', sa.Text(), nullable=True),
        sa.Column('assigned_to', sa.String(length=255), nullable=True),
        sa.Column('decision_notes', sa.Text(), nullable=True),
        sa.Column('deferred_reason', sa.Text(), nullable=True),
        sa.Column('verification_status', sa.String(length=50), server_default='UNVERIFIED', nullable=False),
        sa.Column('verification_evidence', sa.JSON(), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verified_by', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_remediation_recommendations_application_id'), 'remediation_recommendations', ['application_id'], unique=False)
    op.create_index(op.f('ix_remediation_recommendations_category'), 'remediation_recommendations', ['category'], unique=False)
    op.create_index(op.f('ix_remediation_recommendations_organization_id'), 'remediation_recommendations', ['organization_id'], unique=False)
    op.create_index(op.f('ix_remediation_recommendations_calculated_priority'), 'remediation_recommendations', ['calculated_priority'], unique=False)
    op.create_index(op.f('ix_remediation_recommendations_scan_id'), 'remediation_recommendations', ['scan_id'], unique=False)
    op.create_index(op.f('ix_remediation_recommendations_severity'), 'remediation_recommendations', ['severity'], unique=False)
    op.create_index(op.f('ix_remediation_recommendations_status'), 'remediation_recommendations', ['status'], unique=False)
    op.create_index(op.f('ix_remediation_recommendations_title'), 'remediation_recommendations', ['title'], unique=False)
    op.create_index(op.f('ix_remediation_recommendations_vulnerability_id'), 'remediation_recommendations', ['vulnerability_id'], unique=False)

    op.create_table(
        'remediation_history',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('recommendation_id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('from_status', sa.String(length=50), nullable=False),
        sa.Column('to_status', sa.String(length=50), nullable=False),
        sa.Column('actor_email', sa.String(length=255), nullable=True),
        sa.Column('actor_role', sa.String(length=100), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['recommendation_id'], ['remediation_recommendations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_remediation_history_organization_id'), 'remediation_history', ['organization_id'], unique=False)
    op.create_index(op.f('ix_remediation_history_recommendation_id'), 'remediation_history', ['recommendation_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_remediation_history_recommendation_id'), table_name='remediation_history')
    op.drop_index(op.f('ix_remediation_history_organization_id'), table_name='remediation_history')
    op.drop_table('remediation_history')

    op.drop_index(op.f('ix_remediation_recommendations_vulnerability_id'), table_name='remediation_recommendations')
    op.drop_index(op.f('ix_remediation_recommendations_title'), table_name='remediation_recommendations')
    op.drop_index(op.f('ix_remediation_recommendations_status'), table_name='remediation_recommendations')
    op.drop_index(op.f('ix_remediation_recommendations_severity'), table_name='remediation_recommendations')
    op.drop_index(op.f('ix_remediation_recommendations_scan_id'), table_name='remediation_recommendations')
    op.drop_index(op.f('ix_remediation_recommendations_calculated_priority'), table_name='remediation_recommendations')
    op.drop_index(op.f('ix_remediation_recommendations_organization_id'), table_name='remediation_recommendations')
    op.drop_index(op.f('ix_remediation_recommendations_category'), table_name='remediation_recommendations')
    op.drop_index(op.f('ix_remediation_recommendations_application_id'), table_name='remediation_recommendations')
    op.drop_table('remediation_recommendations')

