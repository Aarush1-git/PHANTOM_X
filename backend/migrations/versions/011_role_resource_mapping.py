"""011_role_resource_mapping

Revision ID: 011_role_resource_mapping
Revises: 010_workflow_discovery
Create Date: 2026-11-12 20:44:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.models.base import GUID

# revision identifiers, used by Alembic.
revision: str = '011_role_resource_mapping'
down_revision: Union[str, None] = '010_workflow_discovery'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'role_resource_mappings',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('subject_type', sa.String(length=50), nullable=False),
        sa.Column('subject_id', sa.String(length=100), nullable=True),
        sa.Column('subject_name', sa.String(length=100), nullable=False),
        sa.Column('object_type', sa.String(length=50), nullable=False),
        sa.Column('object_id', sa.String(length=100), nullable=True),
        sa.Column('object_name', sa.String(length=200), nullable=False),
        sa.Column('relationship_type', sa.String(length=50), nullable=False),
        sa.Column('evidence_source', sa.String(length=50), server_default='OBSERVED', nullable=False),
        sa.Column('confidence_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('sample_count', sa.Integer(), server_default='1', nullable=False),
        sa.Column('access_telemetry', sa.JSON(), nullable=False),
        sa.Column('declared_vs_observed', sa.JSON(), nullable=False),
        sa.Column('evidence_references', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='ACTIVE', nullable=False),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'application_id',
            'subject_type',
            'subject_name',
            'relationship_type',
            'object_type',
            'object_name',
            name='uq_role_resource_mapping'
        ),
        sa.CheckConstraint('confidence_score >= 0.0 AND confidence_score <= 1.0', name='chk_mapping_confidence'),
        sa.CheckConstraint('sample_count >= 0', name='chk_mapping_sample_count'),
    )
    op.create_index(op.f('ix_role_resource_mappings_organization_id'), 'role_resource_mappings', ['organization_id'], unique=False)
    op.create_index(op.f('ix_role_resource_mappings_application_id'), 'role_resource_mappings', ['application_id'], unique=False)
    op.create_index('ix_rrm_app_type', 'role_resource_mappings', ['application_id', 'relationship_type'], unique=False)
    op.create_index('ix_rrm_app_source', 'role_resource_mappings', ['application_id', 'evidence_source'], unique=False)
    op.create_index('ix_rrm_app_confidence', 'role_resource_mappings', ['application_id', 'confidence_score'], unique=False)
    op.create_index('ix_rrm_org_app', 'role_resource_mappings', ['organization_id', 'application_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_rrm_org_app', table_name='role_resource_mappings')
    op.drop_index('ix_rrm_app_confidence', table_name='role_resource_mappings')
    op.drop_index('ix_rrm_app_source', table_name='role_resource_mappings')
    op.drop_index('ix_rrm_app_type', table_name='role_resource_mappings')
    op.drop_index(op.f('ix_role_resource_mappings_application_id'), table_name='role_resource_mappings')
    op.drop_index(op.f('ix_role_resource_mappings_organization_id'), table_name='role_resource_mappings')
    op.drop_table('role_resource_mappings')
