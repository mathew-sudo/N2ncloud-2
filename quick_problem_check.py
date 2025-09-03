#!/usr/bin/env python3
"""
Quick Problem Identifier for N2ncloud 2
Identifies the most common issues quickly
"""

import os
import sys
import platform

def check_immediate_problems():
    """Check for immediate obvious problems"""
    
    print("🔍 N2ncloud 2 - Quick Problem Check")
    print("=" * 45)
    
    problems_found = []
    warnings = []
    
    # 1. Check file extensions - common issue
    print("\n📁 File Extension Check:")
    
    # Check if there's a .py file that should be .py
    for file in os.listdir('.'):
        if file == "N2ncloud 2.py":
            print(f"❌ PROBLEM: Found '{file}' - This should be renamed")
            print(f"   File appears to be a batch file with .py extension")
            problems_found.append(f"Incorrect file extension: {file}")
            
            # Check content to confirm
            try:
                with open(file, 'r') as f:
                    content = f.read(100)
                if content.startswith('REM filepath:') or '@echo off' in content:
                    print(f"   ✓ Confirmed: This is a Windows batch file, not Python")
                    print(f"   💡 FIX: Rename to 'N2ncloud 2.bat'")
            except:
                pass
    
    # 2. Check for missing critical Python files
    print("\n🐍 Critical Python Files:")
    critical_files = [
        'n2ncloud_security.py',
        'start_n2ncloud.py', 
        'ai_self_security.py'
    ]
    
    for file in critical_files:
        if os.path.exists(file):
            print(f"✓ {file}")
        else:
            print(f"❌ {file} - MISSING")
            problems_found.append(f"Missing critical file: {file}")
    
    # 3. Check Python version
    print(f"\n🐍 Python Environment:")
    print(f"   Version: {sys.version}")
    
    if sys.version_info < (3, 8):
        print(f"❌ Python version too old: {sys.version_info}")
        problems_found.append("Python version < 3.8")
    else:
        print(f"✓ Python version OK")
    
    # 4. Check basic imports
    print(f"\n📦 Basic Dependencies:")
    
    basic_modules = ['os', 'sys', 'subprocess', 'threading']
    for module in basic_modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError:
            print(f"❌ {module} - MISSING")
            problems_found.append(f"Missing basic module: {module}")
    
    # 5. Check for psutil specifically
    try:
        import psutil
        print(f"✓ psutil (essential)")
    except ImportError:
        print(f"❌ psutil - MISSING (critical dependency)")
        problems_found.append("Missing psutil - install with: pip install psutil")
    
    # 6. Check permissions
    print(f"\n🔐 Permissions:")
    
    if platform.system() == 'Windows':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False
    else:
        is_admin = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    if is_admin:
        print(f"✓ Running with admin privileges")
    else:
        print(f"⚠️ Not running with admin privileges")
        warnings.append("Limited privileges - some features may not work")
    
    # 7. Check directory structure
    print(f"\n📂 Directory Access:")
    
    if platform.system() == 'Windows':
        test_dir = os.environ.get('TEMP', 'C:\\temp')
    else:
        test_dir = '/tmp'
    
    try:
        test_file = os.path.join(test_dir, 'n2ncloud_test.tmp')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        print(f"✓ Can write to {test_dir}")
    except:
        print(f"❌ Cannot write to {test_dir}")
        problems_found.append(f"No write access to {test_dir}")
    
    # Summary
    print(f"\n📊 SUMMARY:")
    print(f"=" * 45)
    
    if problems_found:
        print(f"❌ Found {len(problems_found)} critical problems:")
        for i, problem in enumerate(problems_found, 1):
            print(f"   {i}. {problem}")
        
        print(f"\n🔧 IMMEDIATE ACTIONS NEEDED:")
        
        # File extension fix
        if any("Incorrect file extension" in p for p in problems_found):
            print(f"   1. Rename 'N2ncloud 2.py' to 'N2ncloud 2.bat'")
        
        # Missing files
        missing_files = [p for p in problems_found if "Missing critical file" in p]
        if missing_files:
            print(f"   2. Restore missing files or re-download platform")
        
        # Dependencies
        if any("psutil" in p for p in problems_found):
            print(f"   3. Install psutil: pip install psutil")
        
        # Python version
        if any("Python version" in p for p in problems_found):
            print(f"   4. Upgrade Python to 3.8+")
        
    else:
        print(f"✅ No critical problems found!")
    
    if warnings:
        print(f"\n⚠️ Warnings ({len(warnings)}):")
        for warning in warnings:
            print(f"   • {warning}")
    
    print(f"\n🎯 NEXT STEPS:")
    if problems_found:
        print(f"   1. Fix the problems above")
        print(f"   2. Run this check again")
        print(f"   3. Run full diagnostic: python3 diagnose_problems.py")
    else:
        print(f"   1. Run full diagnostic: python3 diagnose_problems.py")
        print(f"   2. Run system check: python3 check_system.py")
        print(f"   3. Start platform: python3 start_n2ncloud.py --check-only")
    
    print(f"=" * 45)
    
    return len(problems_found) == 0

if __name__ == "__main__":
    success = check_immediate_problems()
    sys.exit(0 if success else 1)