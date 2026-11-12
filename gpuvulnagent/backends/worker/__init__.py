# -*- coding: utf-8 -*-
"""The in-WSL worker.

This package exists so the worker can be imported and unit-tested on Windows; at run time
the single file ``gpu_worker.py`` is copied into the WSL home and executed there by
``/usr/bin/python3``. It imports nothing from the rest of this project.
"""

from . import gpu_worker

__all__ = ["gpu_worker"]
