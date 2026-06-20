#!/usr/bin/env python3
import sys
import os
import platform
import subprocess
from pathlib import Path

def get_python_and_cmd():
    workspace = Path(__file__).resolve().parent
    
    # Try to find a virtual environment in the workspace
    if platform.system() == "Windows":
        venv_python = workspace / ".venv" / "Scripts" / "python.exe"
        if not venv_python.exists():
            venv_python = workspace / "venv" / "Scripts" / "python.exe"
    else:
        venv_python = workspace / ".venv" / "bin" / "python"
        if not venv_python.exists():
            venv_python = workspace / "venv" / "bin" / "python"
            
    # Fallback to the current interpreter running this script
    python_exe = venv_python if venv_python.exists() else Path(sys.executable)
    
    # Formulate command using absolute paths
    cmd = f'"{python_exe}" -m bot_security_news collect'
    return workspace, cmd

def setup_windows(workspace: Path, cmd: str):
    task_name = "BotSecurityNews"
    # Create the command that changes dir and runs the python module
    run_cmd = f'cmd.exe /c "cd /d {workspace} && {cmd}"'
    
    # schtasks command
    # /create - create task
    # /tn - task name
    # /tr - task run command
    # /sc - schedule (daily)
    # /st - start time (08:00)
    # /f - force overwrite
    schtasks_cmd = [
        "schtasks", "/create",
        "/tn", task_name,
        "/tr", run_cmd,
        "/sc", "daily",
        "/st", "08:00",
        "/f"
    ]
    
    print(f"Registering Windows Task Scheduler task: {task_name}")
    print(f"Command to run: {run_cmd}")
    
    try:
        result = subprocess.run(schtasks_cmd, capture_output=True, text=True, check=True)
        print("Success!")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Failed to register Windows Task Scheduler task:")
        print(e.stderr or e.stdout)
        sys.exit(1)

def setup_linux(workspace: Path, cmd: str):
    log_file = workspace / "cron.log"
    # Construct cron line: run at 08:00 daily
    cron_line = f"0 8 * * * cd {workspace} && {cmd} >> {log_file} 2>&1"
    
    print("Registering Linux crontab job...")
    print(f"Cron entry: {cron_line}")
    
    try:
        # Get current crontab
        current_cron = ""
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode == 0:
            current_cron = result.stdout
            
        # Filter out existing bot_security_news cron entries to prevent duplicates
        lines = current_cron.splitlines()
        filtered_lines = [l for l in lines if "bot_security_news" not in l and str(workspace) not in l]
        
        # Append new entry
        filtered_lines.append(cron_line)
        new_cron = "\n".join(filtered_lines) + "\n"
        
        # Write back to crontab
        p = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = p.communicate(input=new_cron)
        
        if p.returncode == 0:
            print("Success! Crontab updated.")
        else:
            print(f"Failed to update crontab: {stderr or stdout}")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error registering cron: {e}")
        sys.exit(1)

def main():
    os_name = platform.system()
    workspace, cmd = get_python_and_cmd()
    
    print(f"Detected OS: {os_name}")
    print(f"Workspace path: {workspace}")
    
    if os_name == "Windows":
        setup_windows(workspace, cmd)
    elif os_name in ("Linux", "Darwin"):
        setup_linux(workspace, cmd)
    else:
        print(f"Unsupported OS: {os_name}")
        sys.exit(1)

if __name__ == "__main__":
    main()
