"""007_playground_sessions

Revision ID: 007_playground_sessions
Revises: 006_time_travel_regression
Create Date: 2026-11-11 12:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.models.base import GUID

revision: str = '007_playground_sessions'
down_revision: Union[str, None] = '006_time_travel_regression'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'playground_sessions',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('parent_session_id', GUID(), nullable=True),
        sa.Column('scenario_id', sa.String(length=100), nullable=False),
        sa.Column('scenario_name', sa.String(length=255), nullable=False),
        sa.Column('scenario_category', sa.String(length=100), nullable=False),
        sa.Column('target_type', sa.String(length=50), server_default='AUTHORIZED_APPLICATION', nullable=False),
        sa.Column('status', sa.String(length=50), server_default='AWAITING_AUTHORIZATION', nullable=False),
        sa.Column('security_result', sa.String(length=50), nullable=True),
        sa.Column('is_authorized', sa.Boolean(), server_default=sa.text('0'), nullable=False),
        sa.Column('authorized_by', sa.String(length=255), nullable=True),
        sa.Column('authorizer_role', sa.String(length=100), nullable=True),
        sa.Column('authorized_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('authorization_token', sa.String(length=255), nullable=True),
        sa.Column('execution_plan', sa.JSON(), nullable=False),
        sa.Column('execution_results', sa.JSON(), nullable=False),
        sa.Column('evidence_references', sa.JSON(), nullable=False),
        sa.Column('safety_decisions', sa.JSON(), nullable=False),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['parent_session_id'], ['playground_sessions.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_playground_sessions_organization_id', 'playground_sessions', ['organization_id'])
    op.create_index('ix_playground_sessions_application_id', 'playground_sessions', ['application_id'])
    op.create_index('ix_playground_sessions_scenario_id', 'playground_sessions', ['scenario_id'])
    op.create_index('ix_playground_sessions_scenario_category', 'playground_sessions', ['scenario_category'])
    op.create_index('ix_playground_sessions_status', 'playground_sessions', ['status'])


def downgrade() -> None:
    op.drop_table('playground_sessions')
