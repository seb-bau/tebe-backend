"""roles

Revision ID: cb1d6ee3500b
Revises: b48004e240e9
Create Date: 2026-02-11 13:36:53.244732

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cb1d6ee3500b'
down_revision = 'b48004e240e9'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'role',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'component_role',
        sa.Column('component_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['component_id'], ['component_catalog_item.id']),
        sa.ForeignKeyConstraint(['role_id'], ['role.id']),
        sa.PrimaryKeyConstraint('component_id', 'role_id')
    )

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_user_role_id_role',   # ✅ Name vergeben
            'role',
            ['role_id'],
            ['id']
        )


def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint('fk_user_role_id_role', type_='foreignkey')
        batch_op.drop_column('role_id')

    op.drop_table('component_role')
    op.drop_table('role')
