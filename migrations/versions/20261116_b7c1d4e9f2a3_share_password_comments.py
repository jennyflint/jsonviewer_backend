"""share password, burn-after-read and comments

Revision ID: b7c1d4e9f2a3
Revises: a3343c161ed1
"""

from __future__ import annotations

import advanced_alchemy.types
import advanced_alchemy.types.datetime
import sqlalchemy as sa
from alembic import op

revision = "b7c1d4e9f2a3"
down_revision = "a3343c161ed1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("shares", sa.Column("password_hash", sa.String(length=200), nullable=True))
    op.add_column(
        "shares",
        sa.Column("burn_after_read", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.add_column(
        "shares",
        sa.Column("comments_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.create_table(
        "share_comments",
        sa.Column("share_id", advanced_alchemy.types.guid.GUID(length=16), nullable=False),
        sa.Column("path", sa.String(length=1000), nullable=True),
        sa.Column("author", sa.String(length=60), nullable=False),
        sa.Column("text", sa.String(length=2000), nullable=False),
        sa.Column("id", advanced_alchemy.types.guid.GUID(length=16), nullable=False),
        sa.Column("sa_orm_sentinel", sa.Integer(), nullable=True),
        sa.Column(
            "created_at", advanced_alchemy.types.datetime.DateTimeUTC(timezone=True), nullable=False
        ),
        sa.Column(
            "updated_at", advanced_alchemy.types.datetime.DateTimeUTC(timezone=True), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["share_id"],
            ["shares.id"],
            name=op.f("fk_share_comments_share_id_shares"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_share_comments")),
    )
    op.create_index(op.f("ix_share_comments_share_id"), "share_comments", ["share_id"])


def downgrade() -> None:
    op.drop_index(op.f("ix_share_comments_share_id"), table_name="share_comments")
    op.drop_table("share_comments")
    op.drop_column("shares", "comments_enabled")
    op.drop_column("shares", "burn_after_read")
    op.drop_column("shares", "password_hash")
