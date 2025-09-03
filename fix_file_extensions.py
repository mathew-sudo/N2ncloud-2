#!/usr/bin/env python3
"""
N2ncloud 2 File Extension Fixer
Fixes common file extension and naming issues
"""

import os
import shutil
import sys

def fix_file_extensions():
    """Fix incorrect file extensions"""
    
    print("🔧 N2ncloud 2 - File Extension Fixer")
    print("=" * 40)
    
    fixes_made = 0
    
    # Check for the specific issue: "N2ncloud 2.py" that's actually a batch file
    problem_file = "N2ncloud 2.py"
    correct_file = "N2ncloud 2.bat"
    
    if os.path.exists(problem_file):
        print(f"\n📁 Found problematic file: {problem_file}")
        
        # Check if it's actually a batch file
        try:
            with open(problem_file, 'r') as f:
                content = f.read(200)
            
            if content.startswith('REM filepath:') or '@echo off' in content or 'echo off' in content:
                print(f"✓ Confirmed: This is a Windows batch file with wrong extension")
                
                # Check if target already exists
                if os.path.exists(correct_file):
                    print(f"⚠️ Target file {correct_file} already exists")
                    
                    # Compare content
                    with open(correct_file, 'r') as f:
                        existing_content = f.read(200)
                    
                    if content.strip() == existing_content.strip():
                        print(f"✓ Files are identical, removing duplicate")
                        os.remove(problem_file)
                        fixes_made += 1
                    else:
                        backup_name = f"{problem_file}.backup"
                        print(f"⚠️ Files differ, creating backup as {backup_name}")
                        shutil.move(problem_file, backup_name)
                        fixes_made += 1
                else:
                    # Rename the file
                    print(f"🔄 Renaming {problem_file} → {correct_file}")
                    shutil.move(problem_file, correct_file)
                    fixes_made += 1
                    print(f"✅ Fixed file extension!")
            else:
                print(f"🤔 File doesn't appear to be a batch file")
                print(f"   First 100 chars: {content[:100]}...")
                
        except Exception as e:
            print(f"❌ Error reading file: {e}")
    else:
        print(f"✓ No file extension issues found")
    
    # Check for other common issues
    print(f"\n🔍 Checking for other file issues...")
    
    # Look for .bat files with .py extension
    for filename in os.listdir('.'):
        if filename.endswith('.py') and filename != problem_file:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                
                if first_line.startswith('@echo off') or first_line.startswith('REM'):
                    print(f"⚠️ Found another batch file with .py extension: {filename}")
                    suggested_name = filename.replace('.py', '.bat')
                    print(f"   Suggested rename: {filename} → {suggested_name}")
                    
            except Exception:
                continue
    
    # Look for Python files with .bat extension
    for filename in os.listdir('.'):
        if filename.endswith('.bat') and 'N2ncloud' not in filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    first_line = f.readline().strip()
                
                if first_line.startswith('#!/usr/bin/env python') or first_line.startswith('"""'):
                    print(f"⚠️ Found Python file with .bat extension: {filename}")
                    suggested_name = filename.replace('.bat', '.py')
                    print(f"   Suggested rename: {filename} → {suggested_name}")
                    
            except Exception:
                continue
    
    # Summary
    print(f"\n📊 SUMMARY:")
    print(f"=" * 40)
    
    if fixes_made > 0:
        print(f"✅ Made {fixes_made} fixes")
        print(f"   File extension issues have been resolved")
    else:
        print(f"✓ No file extension fixes needed")
    
    print(f"\n🎯 NEXT STEPS:")
    print(f"   1. Run quick check: python3 quick_problem_check.py")
    print(f"   2. Run full diagnostic: python3 diagnose_problems.py")
    
    return fixes_made

if __name__ == "__main__":
    fixes = fix_file_extensions()
    print(f"\nFile extension fixer completed with {fixes} fixes made.")
    sys.exit(0)