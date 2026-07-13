#!/usr/bin/env python3
"""
Entry point for the Dependency Security Scanner.
Delegates to src.main via a static import, enabling IDE navigation and static analysis.
"""
import sys
import os

# Add the project root to sys.path so src.main can be imported directly.
# Also add src/ so that src/main.py's internal bare imports (e.g. from config import ...)
# continue to resolve without modification to the src package.
_project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_project_root, "src"))
sys.path.insert(0, _project_root)

from src.main import main

if __name__ == "__main__":
    main()
