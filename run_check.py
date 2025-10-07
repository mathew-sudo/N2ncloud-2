#!/usr/bin/env python3
"""
Run N2ncloud System Check
Simple wrapper to run the system check
"""

if __name__ == "__main__":
    import sys
    from check_system import main
    sys.exit(main())