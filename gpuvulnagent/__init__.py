# -*- coding: utf-8 -*-
"""GPUVulnAgent: an autonomous NVIDIA GPU vulnerability research agent.

The package is independent: it never imports the legacy ``cuda_poc_generator`` tree, and
every path it needs (toolchain, research archive, artifacts) is resolved from the project
root or from configuration.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
