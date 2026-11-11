"""003_audit_logs_execution_history

Revision ID: 003_audit_logs_execution_history
Revises: 002_scope_safety_management
Create Date: 2026-11-10 13:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.models.base import GUID

revision: str = '003_audit_logs_execution_history'
down_revision: Union[str, None] = '002_scope_safety_management'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Expand audit_logs with structured categorization and hash-chain columns
    with op.batch_alter_table('audit_logs') as batch_op:
        batch_op.add_column(sa.Column('category', sa.String(length=50), nullable=False, server_default='PLATFORM'))
        batch_op.add_column(sa.Column('event_type', sa.String(length=100), nullable=False, server_default='GENERAL_AUDIT'))
        batch_op.add_column(sa.Column('status', sa.String(length=50), nullable=False, server_default='SUCCESS'))
        batch_op.add_column(sa.Column('severity', sa.String(length=50), nullable=False, server_default='INFO'))
        batch_op.add_column(sa.Column('actor_email', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('actor_role', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('application_id', GUID(), nullable=True))
        batch_op.add_column(sa.Column('scan_id', GUID(), nullable=True))
        batch_op.add_column(sa.Column('source_module', sa.String(length=100), nullable=False, server_default='SECURITY_OPERATIONS'))
        batch_op.add_column(sa.Column('correlation_id', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('event_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('prev_event_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('sequence_number', sa.Integer(), nullable=False, server_default='1'))
        batch_op.create_index('ix_audit_logs_sequence_number', ['sequence_number'])
        batch_op.create_index('ix_audit_logs_category', ['category'])
        batch_op.create_index('ix_audit_logs_event_type', ['event_type'])
        batch_op.create_index('ix_audit_logs_status', ['status'])
        batch_op.create_index('ix_audit_logs_severity', ['severity'])
        batch_op.create_index('ix_audit_logs_application_id', ['application_id'])
        batch_op.create_index('ix_audit_logs_scan_id', ['scan_id'])
        batch_op.create_index('ix_audit_logs_event_hash', ['event_hash'])

    # 2. Backfill existing historical audit records deterministically per organization
    conn = op.get_bind()
    org_rows = conn.execute(sa.text("SELECT DISTINCT organization_id FROM audit_logs")).fetchall()
    for org_row in org_rows:
        org_id = org_row[0]
        records = conn.execute(
            sa.text("SELECT id FROM audit_logs WHERE organization_id = :org_id ORDER BY created_at ASC, id ASC"),
            {"org_id": org_id}
        ).fetchall()
        for seq, rec in enumerate(records, start=1):
            conn.execute(
                sa.text("UPDATE audit_logs SET sequence_number = :seq WHERE id = :id"),
                {"seq": seq, "id": rec[0]}
            )

    # 3. Pre-constraint verification: Ensure no duplicates exist before enforcing uniqueness
    duplicate_check = conn.execute(sa.text("""
        SELECT organization_id, sequence_number, COUNT(*) as cnt
        FROM audit_logs
        GROUP BY organization_id, sequence_number
        HAVING COUNT(*) > 1
    """)).fetchall()
    if duplicate_check:
        raise RuntimeError(
            f"Migration 003 aborting: Found duplicate sequence numbers after backfill: {duplicate_check}"
        )

    # 4. Add unique constraint to enforce deterministic sequence per organization
    with op.batch_alter_table('audit_logs') as batch_op:
        batch_op.create_unique_constraint('uq_audit_logs_org_sequence', ['organization_id', 'sequence_number'])

    # 5. Dedicated Scan Execution Records table
    op.create_table(
        'scan_execution_records',
        sa.Column('id', GUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('organization_id', GUID(), nullable=False),
        sa.Column('scan_id', GUID(), nullable=False),
        sa.Column('application_id', GUID(), nullable=False),
        sa.Column('initiating_user_id', GUID(), nullable=True),
        sa.Column('initiating_user', sa.String(length=255), nullable=True),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('final_status', sa.String(length=50), nullable=False, server_default='QUEUED'),
        sa.Column('tests_executed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('tests_blocked', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('verified_findings', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failure_reason', sa.String(length=1000), nullable=True),
        sa.Column('lifecycle_events', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['initiating_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_exec_records_org_id', 'scan_execution_records', ['organization_id'])
    op.create_index('ix_scan_exec_records_scan_id', 'scan_execution_records', ['scan_id'])
    op.create_index('ix_scan_exec_records_app_id', 'scan_execution_records', ['application_id'])
    op.create_index('ix_scan_exec_records_status', 'scan_execution_records', ['final_status'])


def downgrade() -> None:
    op.drop_table('scan_execution_records')
    with op.batch_alter_table('audit_logs') as batch_op:
        try:
            batch_op.drop_constraint('uq_audit_logs_org_sequence', type_='unique')
        except Exception:
            pass
        batch_op.drop_index('ix_audit_logs_sequence_number')
        batch_op.drop_index('ix_audit_logs_event_hash')
        batch_op.drop_index('ix_audit_logs_scan_id')
        batch_op.drop_index('ix_audit_logs_application_id')
        batch_op.drop_index('ix_audit_logs_severity')
        batch_op.drop_index('ix_audit_logs_status')
        batch_op.drop_index('ix_audit_logs_event_type')
        batch_op.drop_index('ix_audit_logs_category')
        batch_op.drop_column('prev_event_hash')
        batch_op.drop_column('event_hash')
        batch_op.drop_column('sequence_number')
        batch_op.drop_column('correlation_id')
        batch_op.drop_column('source_module')
        batch_op.drop_column('scan_id')
        batch_op.drop_column('application_id')
        batch_op.drop_column('actor_role')
        batch_op.drop_column('actor_email')
        batch_op.drop_column('severity')
        batch_op.drop_column('status')
        batch_op.drop_column('event_type')
        batch_op.drop_column('category')

