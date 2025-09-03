import os
import subprocess
import sys

print("N2ncloud 2 Security Platform - Quick Verification")
print("=" * 55)

# List all files in directory
print("\n📁 Directory Contents:")
files = [f for f in os.listdir('.') if os.path.isfile(f)]
files.sort()

python_files = [f for f in files if f.endswith('.py')]
config_files = [f for f in files if f.endswith('.ini') or f.endswith('.md')]
script_files = [f for f in files if f.endswith('.bat') or f.endswith('.sh')]

print(f"\nPython files ({len(python_files)}):")
for f in python_files:
    size = os.path.getsize(f)
    print(f"  {f:30} {size:>8,} bytes")

print(f"\nConfiguration/Documentation ({len(config_files)}):")
for f in config_files:
    size = os.path.getsize(f)
    print(f"  {f:30} {size:>8,} bytes")

print(f"\nScript files ({len(script_files)}):")
for f in script_files:
    size = os.path.getsize(f)
    print(f"  {f:30} {size:>8,} bytes")

# Check Python basics
print(f"\n🐍 Python Environment:")
print(f"  Version: {sys.version}")
print(f"  Executable: {sys.executable}")

# Try importing key modules
print(f"\n📦 Key Dependencies:")
modules_to_check = ['os', 'sys', 'subprocess', 'threading', 'hashlib', 'json', 'time', 're']

for module in modules_to_check:
    try:
        __import__(module)
        print(f"  ✓ {module}")
    except ImportError:
        print(f"  ❌ {module}")

# Check psutil specifically
try:
    import psutil
    print(f"  ✓ psutil (processes: {len(list(psutil.process_iter()))})")
except ImportError:
    print(f"  ❌ psutil - Need to install: pip install psutil")

print("\n" + "=" * 55)
print("Quick verification completed!")

# Check if main module exists and can be loaded
if os.path.exists('n2ncloud_security.py'):
    print("✅ Main security module found")
    print("Ready to run system check: python3 check_system.py")
else:
    print("❌ Main security module missing")

print("=" * 55)