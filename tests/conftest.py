"""
Configure pytest environment for chaincraft tests.

This file ensures the root directory is in the Python path
so that imports work correctly in CI and local environments.
"""

import os
import sys

# Add the project root directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 