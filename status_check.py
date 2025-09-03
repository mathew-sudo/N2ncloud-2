#!/usr/bin/env python3
"""
Quick N2ncloud Status Check
"""

import os
import sys
import platform

print("=" * 60)
print("N2ncloud 2 Security Platform - Status Check")
print("=" * 60)

# Check current directory
print(f"Current directory: {os.getcwd()}")
print(f"Python version: {sys.version}")
print(f"Platform: {platform.system()} {platform.release()}")

# Check files
print("\n📁 Files in current directory:")
files = os.listdir('.')
for f in sorted(files):
    if f.endswith('.py'):
        print(f"  ✓ {f}")

# Check core modules
print("\n🛡️ Security Modules:")
security_modules = [
    'n2ncloud_security.py',
    'ai_self_security.py', 
    'self_defense.py',
    'self_offense.py',
    'trojan_hunter.py',
    'self_repair.py',
    'system_file_repair.py',
    'bookworm_killer.py',
    'xss_protection.py'
]

for module in security_modules:
    if os.path.exists(module):
        size = os.path.getsize(module)
        print(f"  ✓ {module} ({size:,} bytes)")
    else:
        print(f"  ❌ {module} - Missing")

# Check config
print("\n⚙️ Configuration:")
if os.path.exists('n2ncloud_config.ini'):
    print("  ✓ n2ncloud_config.ini")
else:
    print("  ❌ n2ncloud_config.ini - Missing")

# Check documentation
print("\n📚 Documentation:")
docs = ['README.md', 'WINDOWS_INSTALL.md']
for doc in docs:
    if os.path.exists(doc):
        print(f"  ✓ {doc}")
    else:
        print(f"  ❌ {doc} - Missing")

print("\n" + "=" * 60)
print("Status check completed!")
print("For detailed check, run: python3 check_system.py")
print("=" * 60)