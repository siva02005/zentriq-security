"""pytest configuration for ZENTRIQ tests."""
import sys
import os

# Ensure zentriq root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
