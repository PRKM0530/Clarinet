"""
clarinet/models
All SQLAlchemy ORM models.

The original tables live in core.py and are shared by every feature, so treat
that file as frozen. When a feature needs new tables, add a module of your own
here (for example models/security.py) and it is picked up automatically, so no
one has to edit this file.
"""

import importlib
import pkgutil

from clarinet.models.core import *  # noqa: F401,F403  (keeps `from clarinet.models import X` working)

for _mod in pkgutil.iter_modules(__path__):
    if _mod.name != "core":
        importlib.import_module(f"{__name__}.{_mod.name}")
