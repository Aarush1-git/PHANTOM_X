"""010_workflow_discovery

Revision ID: 010_workflow_discovery
Revises: 009_behavioral_digital_twin
Create Date: 2026-11-12 19:48:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.models.base import GUID

# revision identifiers, used by Alembic.
revision: str = '010_workflow_discovery'
down_revision: Union[str, None] = '009_behavioral_digital_twin'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'discovered_workflows',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('description', sa.String(length=1000), nullable=True),
        sa.Column('workflow_type', sa.String(length=50), server_default='STANDARD', nullable=False),
        sa.Column('status', sa.String(length=50), server_default='DISCOVERED', nullable=False),
        sa.Column('confidence_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('sample_count', sa.Integer(), server_default='1', nullable=False),
        sa.Column('step_count', sa.Integer(), server_default='1', nullable=False),
        sa.Column('entry_endpoint_id', GUID(), nullable=True),
        sa.Column('terminal_endpoint_id', GUID(), nullable=True),
        sa.Column('is_incomplete', sa.Boolean(), server_default='0', nullable=False),
        sa.Column('dropout_step_index', sa.Integer(), nullable=True),
        sa.Column('graph_data', sa.JSON(), nullable=False),
        sa.Column('steps_sequence', sa.JSON(), nullable=False),
        sa.Column('variations', sa.JSON(), nullable=False),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['entry_endpoint_id'], ['discovered_endpoints.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['terminal_endpoint_id'], ['discovered_endpoints.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.CheckConstraint('confidence_score >= 0.0 AND confidence_score <= 1.0', name='chk_workflow_confidence'),
        sa.CheckConstraint('sample_count >= 0', name='chk_workflow_sample_count'),
    )
    op.create_index(op.f('ix_discovered_workflows_organization_id'), 'discovered_workflows', ['organization_id'], unique=False)
    op.create_index(op.f('ix_discovered_workflows_application_id'), 'discovered_workflows', ['application_id'], unique=False)
    op.create_index(op.f('ix_discovered_workflows_entry_endpoint_id'), 'discovered_workflows', ['entry_endpoint_id'], unique=False)
    op.create_index(op.f('ix_discovered_workflows_terminal_endpoint_id'), 'discovered_workflows', ['terminal_endpoint_id'], unique=False)
    op.create_index('ix_dw_app_status', 'discovered_workflows', ['application_id', 'status'], unique=False)
    op.create_index('ix_dw_app_confidence', 'discovered_workflows', ['application_id', 'confidence_score'], unique=False)
    op.create_index('ix_dw_app_created', 'discovered_workflows', ['application_id', 'created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_dw_app_created', table_name='discovered_workflows')
    op.drop_index('ix_dw_app_confidence', table_name='discovered_workflows')
    op.drop_index('ix_dw_app_status', table_name='discovered_workflows')
    op.drop_index(op.f('ix_discovered_workflows_terminal_endpoint_id'), table_name='discovered_workflows')
    op.drop_index(op.f('ix_discovered_workflows_entry_endpoint_id'), table_name='discovered_workflows')
    op.drop_index(op.f('ix_discovered_workflows_application_id'), table_name='discovered_workflows')
    op.drop_index(op.f('ix_discovered_workflows_organization_id'), table_name='discovered_workflows')
    op.drop_table('discovered_workflows')
