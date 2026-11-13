"""009_behavioral_digital_twin

Revision ID: 009_behavioral_digital_twin
Revises: 008_remediation_recommendations
Create Date: 2026-11-12 17:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.models.base import GUID

# revision identifiers, used by Alembic.
revision: str = '009_behavioral_digital_twin'
down_revision: Union[str, None] = '008_remediation_recommendations'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. behavioral_observations
    op.create_table(
        'behavioral_observations',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('endpoint_id', GUID(), nullable=True),
        sa.Column('method', sa.String(length=20), nullable=False),
        sa.Column('normalized_path', sa.String(length=500), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('sanitized_request_schema', sa.JSON(), nullable=False),
        sa.Column('sanitized_response_schema', sa.JSON(), nullable=False),
        sa.Column('latency_ms', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('session_token_hash', sa.String(length=64), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['endpoint_id'], ['discovered_endpoints.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_behavioral_observations_application_id'), 'behavioral_observations', ['application_id'], unique=False)
    op.create_index(op.f('ix_behavioral_observations_endpoint_id'), 'behavioral_observations', ['endpoint_id'], unique=False)
    op.create_index(op.f('ix_behavioral_observations_normalized_path'), 'behavioral_observations', ['normalized_path'], unique=False)
    op.create_index(op.f('ix_behavioral_observations_organization_id'), 'behavioral_observations', ['organization_id'], unique=False)
    op.create_index(op.f('ix_behavioral_observations_session_token_hash'), 'behavioral_observations', ['session_token_hash'], unique=False)
    op.create_index('ix_obs_app_norm_path', 'behavioral_observations', ['application_id', 'normalized_path'], unique=False)
    op.create_index('ix_obs_app_observed_at', 'behavioral_observations', ['application_id', 'observed_at'], unique=False)

    # 2. behavioral_baselines
    op.create_table(
        'behavioral_baselines',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='DRAFT', nullable=False),
        sa.Column('sample_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('confidence_score', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('endpoint_profiles', sa.JSON(), nullable=False),
        sa.Column('transition_matrix', sa.JSON(), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('confidence_score >= 0.0 AND confidence_score <= 1.0', name='chk_baseline_confidence'),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('application_id', 'version', name='uq_behavioral_baseline_app_version')
    )
    op.create_index(op.f('ix_behavioral_baselines_application_id'), 'behavioral_baselines', ['application_id'], unique=False)
    op.create_index(op.f('ix_behavioral_baselines_organization_id'), 'behavioral_baselines', ['organization_id'], unique=False)
    op.create_index(op.f('ix_behavioral_baselines_status'), 'behavioral_baselines', ['status'], unique=False)
    op.create_index('ix_baseline_app_status', 'behavioral_baselines', ['application_id', 'status'], unique=False)

    # 3. behavioral_transitions
    op.create_table(
        'behavioral_transitions',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('baseline_id', GUID(), nullable=False),
        sa.Column('from_endpoint_id', GUID(), nullable=True),
        sa.Column('to_endpoint_id', GUID(), nullable=False),
        sa.Column('probability', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('observation_count', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('probability >= 0.0 AND probability <= 1.0', name='chk_transition_probability'),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['baseline_id'], ['behavioral_baselines.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['from_endpoint_id'], ['discovered_endpoints.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['to_endpoint_id'], ['discovered_endpoints.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_behavioral_transitions_application_id'), 'behavioral_transitions', ['application_id'], unique=False)
    op.create_index(op.f('ix_behavioral_transitions_baseline_id'), 'behavioral_transitions', ['baseline_id'], unique=False)
    op.create_index(op.f('ix_behavioral_transitions_from_endpoint_id'), 'behavioral_transitions', ['from_endpoint_id'], unique=False)
    op.create_index(op.f('ix_behavioral_transitions_organization_id'), 'behavioral_transitions', ['organization_id'], unique=False)
    op.create_index(op.f('ix_behavioral_transitions_to_endpoint_id'), 'behavioral_transitions', ['to_endpoint_id'], unique=False)
    op.create_index('ix_trans_baseline_endpoints', 'behavioral_transitions', ['baseline_id', 'from_endpoint_id', 'to_endpoint_id'], unique=False)

    # 4. behavioral_anomalies
    op.create_table(
        'behavioral_anomalies',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('baseline_id', GUID(), nullable=True),
        sa.Column('endpoint_id', GUID(), nullable=True),
        sa.Column('anomaly_type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=50), server_default='MEDIUM', nullable=False),
        sa.Column('confidence', sa.Float(), server_default='0.8', nullable=False),
        sa.Column('evidence_data', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=50), server_default='OPEN', nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint('confidence >= 0.0 AND confidence <= 1.0', name='chk_anomaly_confidence'),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['baseline_id'], ['behavioral_baselines.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['endpoint_id'], ['discovered_endpoints.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_behavioral_anomalies_application_id'), 'behavioral_anomalies', ['application_id'], unique=False)
    op.create_index(op.f('ix_behavioral_anomalies_baseline_id'), 'behavioral_anomalies', ['baseline_id'], unique=False)
    op.create_index(op.f('ix_behavioral_anomalies_endpoint_id'), 'behavioral_anomalies', ['endpoint_id'], unique=False)
    op.create_index(op.f('ix_behavioral_anomalies_organization_id'), 'behavioral_anomalies', ['organization_id'], unique=False)
    op.create_index(op.f('ix_behavioral_anomalies_status'), 'behavioral_anomalies', ['status'], unique=False)
    op.create_index('ix_anomaly_app_status', 'behavioral_anomalies', ['application_id', 'status'], unique=False)
    op.create_index('ix_anomaly_detected_at', 'behavioral_anomalies', ['detected_at'], unique=False)


def downgrade() -> None:
    # 4. behavioral_anomalies
    op.drop_index('ix_anomaly_detected_at', table_name='behavioral_anomalies')
    op.drop_index('ix_anomaly_app_status', table_name='behavioral_anomalies')
    op.drop_index(op.f('ix_behavioral_anomalies_status'), table_name='behavioral_anomalies')
    op.drop_index(op.f('ix_behavioral_anomalies_organization_id'), table_name='behavioral_anomalies')
    op.drop_index(op.f('ix_behavioral_anomalies_endpoint_id'), table_name='behavioral_anomalies')
    op.drop_index(op.f('ix_behavioral_anomalies_baseline_id'), table_name='behavioral_anomalies')
    op.drop_index(op.f('ix_behavioral_anomalies_application_id'), table_name='behavioral_anomalies')
    op.drop_table('behavioral_anomalies')

    # 3. behavioral_transitions
    op.drop_index('ix_trans_baseline_endpoints', table_name='behavioral_transitions')
    op.drop_index(op.f('ix_behavioral_transitions_to_endpoint_id'), table_name='behavioral_transitions')
    op.drop_index(op.f('ix_behavioral_transitions_organization_id'), table_name='behavioral_transitions')
    op.drop_index(op.f('ix_behavioral_transitions_from_endpoint_id'), table_name='behavioral_transitions')
    op.drop_index(op.f('ix_behavioral_transitions_baseline_id'), table_name='behavioral_transitions')
    op.drop_index(op.f('ix_behavioral_transitions_application_id'), table_name='behavioral_transitions')
    op.drop_table('behavioral_transitions')

    # 2. behavioral_baselines
    op.drop_index('ix_baseline_app_status', table_name='behavioral_baselines')
    op.drop_index(op.f('ix_behavioral_baselines_status'), table_name='behavioral_baselines')
    op.drop_index(op.f('ix_behavioral_baselines_organization_id'), table_name='behavioral_baselines')
    op.drop_index(op.f('ix_behavioral_baselines_application_id'), table_name='behavioral_baselines')
    op.drop_table('behavioral_baselines')

    # 1. behavioral_observations
    op.drop_index('ix_obs_app_observed_at', table_name='behavioral_observations')
    op.drop_index('ix_obs_app_norm_path', table_name='behavioral_observations')
    op.drop_index(op.f('ix_behavioral_observations_session_token_hash'), table_name='behavioral_observations')
    op.drop_index(op.f('ix_behavioral_observations_organization_id'), table_name='behavioral_observations')
    op.drop_index(op.f('ix_behavioral_observations_normalized_path'), table_name='behavioral_observations')
    op.drop_index(op.f('ix_behavioral_observations_endpoint_id'), table_name='behavioral_observations')
    op.drop_index(op.f('ix_behavioral_observations_application_id'), table_name='behavioral_observations')
    op.drop_table('behavioral_observations')
