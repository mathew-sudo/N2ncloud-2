#!/usr/bin/env python3
"""
N2ncloud 2 Enhanced Command Interface
Advanced command-line interface for security operations
"""

import sys
import os
import argparse
import json
import time
from datetime import datetime

# Import security modules
try:
    from security_procedures import security_procedures
    from n2ncloud_security import N2ncloudSecurityPlatform
    from ai_self_security import AISelfSecurity
    from trojan_hunter import TrojanHunterKiller
    from bookworm_killer import BookwormKiller
    from xss_protection import XSSProtection
except ImportError as e:
    print(f"Warning: Could not import module: {e}")

class N2ncloudCommander:
    """Enhanced command interface for N2ncloud Security Platform"""
    
    def __init__(self):
        self.platform = None
        self.command_history = []
        self.active_sessions = {}
        
    def initialize_platform(self):
        """Initialize the security platform"""
        try:
            self.platform = N2ncloudSecurityPlatform()
            return True
        except Exception as e:
            print(f"Error initializing platform: {e}")
            return False
    
    def execute_security_command(self, command, args=None):
        """Execute a security command"""
        if args is None:
            args = []
            
        try:
            result = security_procedures.execute_procedure(command, *args)
            
            # Log command execution
            self.command_history.append({
                'command': command,
                'args': args,
                'timestamp': datetime.now().isoformat(),
                'result': 'success' if result else 'failed'
            })
            
            return result
        except Exception as e:
            print(f"Command execution failed: {e}")
            return False
    
    def list_all_commands(self):
        """List all available commands"""
        print("\n🛡️ N2NCLOUD 2 SECURITY PLATFORM - COMMAND CENTER")
        print("=" * 70)
        
        # Security Procedures Commands
        commands = security_procedures.get_all_commands()
        
        for category, command_list in commands.items():
            print(f"\n🔒 {category.upper()}")
            print("-" * 50)
            for i, command in enumerate(command_list, 1):
                cmd_name = command.split(' - ')[0]
                cmd_desc = command.split(' - ')[1] if ' - ' in command else 'No description'
                print(f"  {i:2d}. {cmd_name:25} - {cmd_desc}")
        
        # Platform Management Commands
        print(f"\n🚀 PLATFORM MANAGEMENT")
        print("-" * 50)
        management_commands = [
            "start_platform - Start the N2ncloud security platform",
            "stop_platform - Stop the security platform",
            "restart_platform - Restart the platform",
            "platform_status - Show platform status",
            "threat_level - Display current threat level",
            "system_health - Show system health metrics",
            "update_config - Update platform configuration",
            "export_logs - Export security logs",
            "import_rules - Import custom security rules",
            "backup_config - Backup current configuration",
            "performance_monitor - Start performance monitoring",
            "system_update - Check and apply system updates",
            "maintenance_mode - Enter maintenance mode"
        ]
        
        for i, command in enumerate(management_commands, 1):
            cmd_name = command.split(' - ')[0]
            cmd_desc = command.split(' - ')[1]
            print(f"  {i:2d}. {cmd_name:25} - {cmd_desc}")
        
        # Specialized Module Commands
        print(f"\n🎯 SPECIALIZED MODULES")
        print("-" * 50)
        module_commands = [
            "ai_scan - Run AI-powered security scan",
            "trojan_hunt - Execute trojan hunting procedures",
            "bookworm_kill - Activate bookworm killer",
            "xss_protect - Enable XSS protection",
            "memory_dump - Create system memory dump",
            "process_analysis - Analyze running processes",
            "network_map - Map network topology",
            "file_integrity - Check file integrity",
            "crypto_audit - Audit cryptographic implementations",
            "privilege_check - Check privilege escalation vectors"
        ]
        
        for i, command in enumerate(module_commands, 1):
            cmd_name = command.split(' - ')[0]
            cmd_desc = command.split(' - ')[1]
            print(f"  {i:2d}. {cmd_name:25} - {cmd_desc}")
        
        # Advanced Operations
        print(f"\n⚡ ADVANCED OPERATIONS")
        print("-" * 50)
        advanced_commands = [
            "stealth_mode - Enable stealth operation mode",
            "counter_intel - Counter-intelligence operations",
            "deep_scan - Deep system penetration scan",
            "threat_hunt - Proactive threat hunting",
            "incident_sim - Simulate security incidents",
            "red_team - Red team simulation",
            "blue_team - Blue team defense simulation",
            "purple_team - Purple team collaboration",
            "forensic_mode - Enable forensic analysis mode",
            "war_room - Activate security war room"
        ]
        
        for i, command in enumerate(advanced_commands, 1):
            cmd_name = command.split(' - ')[0]
            cmd_desc = command.split(' - ')[1]
            print(f"  {i:2d}. {cmd_name:25} - {cmd_desc}")
        
        print("\n" + "=" * 70)
        print("Usage Examples:")
        print("  python3 n2ncloud_commander.py --command emergency_lockdown")
        print("  python3 n2ncloud_commander.py --command threat_containment --args ip:1.2.3.4")
        print("  python3 n2ncloud_commander.py --list-commands")
        print("  python3 n2ncloud_commander.py --interactive")
        print("=" * 70)
    
    def interactive_mode(self):
        """Run interactive command mode"""
        print("\n🎮 N2NCLOUD 2 INTERACTIVE COMMAND MODE")
        print("=" * 50)
        print("Type 'help' for commands, 'exit' to quit")
        print("=" * 50)
        
        while True:
            try:
                command = input("\nN2ncloud> ").strip()
                
                if command.lower() in ['exit', 'quit', 'q']:
                    print("Exiting N2ncloud Commander...")
                    break
                
                elif command.lower() in ['help', 'h', '?']:
                    self.show_interactive_help()
                
                elif command.lower() == 'status':
                    self.show_platform_status()
                
                elif command.lower() == 'history':
                    self.show_command_history()
                
                elif command.lower() == 'clear':
                    os.system('clear' if os.name != 'nt' else 'cls')
                
                elif command.lower().startswith('exec '):
                    cmd_parts = command[5:].split()
                    if cmd_parts:
                        result = self.execute_security_command(cmd_parts[0], cmd_parts[1:])
                        print(f"Command result: {result}")
                
                elif command.lower() == 'emergency':
                    print("🚨 EMERGENCY PROTOCOLS AVAILABLE:")
                    emergency_commands = [
                        'emergency_lockdown', 'system_isolation', 
                        'threat_containment', 'incident_response'
                    ]
                    for i, cmd in enumerate(emergency_commands, 1):
                        print(f"  {i}. {cmd}")
                    
                    choice = input("Select emergency protocol (1-4) or 'cancel': ")
                    if choice.isdigit() and 1 <= int(choice) <= 4:
                        selected_cmd = emergency_commands[int(choice) - 1]
                        confirm = input(f"Execute {selected_cmd}? (yes/no): ")
                        if confirm.lower() == 'yes':
                            result = self.execute_security_command(selected_cmd)
                            print(f"Emergency protocol executed: {result}")
                
                elif command.lower() == 'scan':
                    print("🔍 Available Scans:")
                    scan_types = [
                        'deep_system_scan', 'vulnerability_assessment',
                        'malware_sandbox', 'network_reconnaissance'
                    ]
                    for i, scan in enumerate(scan_types, 1):
                        print(f"  {i}. {scan}")
                    
                    choice = input("Select scan type (1-4): ")
                    if choice.isdigit() and 1 <= int(choice) <= 4:
                        selected_scan = scan_types[int(choice) - 1]
                        print(f"Executing {selected_scan}...")
                        result = self.execute_security_command(selected_scan)
                        print(f"Scan completed: {result}")
                
                elif command.lower() == 'monitor':
                    print("📊 Starting real-time monitoring...")
                    self.real_time_monitor()
                
                elif command:
                    print(f"Unknown command: {command}")
                    print("Type 'help' for available commands")
                
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit properly.")
            except Exception as e:
                print(f"Error: {e}")
    
    def show_interactive_help(self):
        """Show interactive mode help"""
        print("\n📚 INTERACTIVE MODE COMMANDS:")
        print("-" * 40)
        print("  help          - Show this help")
        print("  status        - Platform status")
        print("  history       - Command history")
        print("  clear         - Clear screen")
        print("  emergency     - Emergency protocols")
        print("  scan          - Security scans")
        print("  monitor       - Real-time monitoring")
        print("  exec <cmd>    - Execute security command")
        print("  exit          - Exit interactive mode")
        print("-" * 40)
    
    def show_platform_status(self):
        """Show platform status"""
        print("\n📊 PLATFORM STATUS:")
        print("-" * 30)
        print(f"  Threat Level: {security_procedures.threat_level}")
        print(f"  Active Procedures: {len(security_procedures.active_procedures)}")
        print(f"  Commands Executed: {len(self.command_history)}")
        print(f"  Platform Status: {'Running' if self.platform else 'Not Initialized'}")
        print(f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def show_command_history(self):
        """Show command execution history"""
        print("\n📜 COMMAND HISTORY:")
        print("-" * 40)
        if not self.command_history:
            print("  No commands executed yet")
        else:
            for i, cmd in enumerate(self.command_history[-10:], 1):  # Last 10 commands
                timestamp = cmd['timestamp'][:19]  # Remove microseconds
                print(f"  {i:2d}. {cmd['command']:20} - {cmd['result']:8} - {timestamp}")
    
    def real_time_monitor(self):
        """Real-time monitoring mode"""
        print("🔴 REAL-TIME MONITORING ACTIVE")
        print("Press Ctrl+C to stop monitoring")
        print("-" * 40)
        
        try:
            while True:
                # Simple monitoring - show system metrics
                import psutil
                
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                
                print(f"\r CPU: {cpu_percent:5.1f}% | Memory: {memory.percent:5.1f}% | "
                      f"Time: {datetime.now().strftime('%H:%M:%S')}", end='', flush=True)
                
                # Check for high resource usage
                if cpu_percent > 90:
                    print(f"\n⚠️  HIGH CPU USAGE DETECTED: {cpu_percent}%")
                
                if memory.percent > 90:
                    print(f"\n⚠️  HIGH MEMORY USAGE DETECTED: {memory.percent}%")
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n\n🔴 Monitoring stopped")

def main():
    """Main command interface"""
    parser = argparse.ArgumentParser(
        description="N2ncloud 2 Security Platform Commander",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list-commands              # List all available commands
  %(prog)s --interactive                # Start interactive mode
  %(prog)s --command emergency_lockdown # Execute emergency lockdown
  %(prog)s --command threat_containment --args "ip:192.168.1.100"
        """
    )
    
    parser.add_argument('--list-commands', '-l', action='store_true',
                       help='List all available security commands')
    
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Start interactive command mode')
    
    parser.add_argument('--command', '-c', type=str,
                       help='Execute specific security command')
    
    parser.add_argument('--args', '-a', type=str, nargs='*',
                       help='Arguments for the command')
    
    parser.add_argument('--platform-init', action='store_true',
                       help='Initialize the security platform')
    
    parser.add_argument('--status', '-s', action='store_true',
                       help='Show platform status')
    
    parser.add_argument('--emergency', '-e', action='store_true',
                       help='Show emergency commands only')
    
    args = parser.parse_args()
    
    # Create commander instance
    commander = N2ncloudCommander()
    
    # Handle arguments
    if args.platform_init:
        print("Initializing N2ncloud Security Platform...")
        if commander.initialize_platform():
            print("✅ Platform initialized successfully")
        else:
            print("❌ Platform initialization failed")
        return
    
    if args.list_commands:
        commander.list_all_commands()
        return
    
    if args.emergency:
        print("\n🚨 EMERGENCY SECURITY COMMANDS")
        print("=" * 40)
        emergency_commands = [
            'emergency_lockdown - Complete system lockdown',
            'incident_response - Automated incident response',
            'threat_containment - Contain identified threats',
            'system_isolation - Isolate system from network',
            'emergency_backup - Create emergency backup'
        ]
        for cmd in emergency_commands:
            print(f"  🔴 {cmd}")
        print("=" * 40)
        return
    
    if args.status:
        commander.show_platform_status()
        return
    
    if args.command:
        print(f"Executing command: {args.command}")
        command_args = args.args if args.args else []
        result = commander.execute_security_command(args.command, command_args)
        print(f"Command result: {result}")
        return
    
    if args.interactive:
        commander.interactive_mode()
        return
    
    # Default: show help
    parser.print_help()
    print("\n💡 Quick start:")
    print("  python3 n2ncloud_commander.py --list-commands")
    print("  python3 n2ncloud_commander.py --interactive")

if __name__ == "__main__":
    main()