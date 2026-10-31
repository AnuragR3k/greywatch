"""Greywatch schema migration modules.

Each module in this package implements one migration. A migration module
exposes a ``MIGRATION`` descriptor and an ``up(connection)`` function.

Migration modules are **never** imported eagerly by the application. The
future migration runner will load the appropriate module per registry entry,
start its own transaction, and call ``up(connection)``.
"""
