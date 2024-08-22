import subprocess
import os
from typing import List
from header import *

path_to_data_folder         = r"data"
path_to_sysutils_folder     = r"sysutils"


def execute_terminal_command(command: str, name: str = 'powershell'):
    """Execute a str as a command"""
    if name.lower() == 'cmd':
        process = subprocess.run(command, shell=True, text=True, capture_output=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif name.lower() == 'powershell':
        process = subprocess.run(['powershell', '-Command', command], text=True, capture_output=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        raise ValueError("Invalid terminal name. Use 'cmd' or 'powershell'.")

    return process.returncode

def get_pid_data():
    """ Get the PID list that is running
        
        basic usage tasklist
        
        filter   tasklist | findstr "<PID>" 

        tasklist | ForEach-Object {
            if ($_ -match "^\\s*Image Name") { return }
            if ($_ -match "^\\s*$") { return }

            if ($_ -match "^(?<ImageName>[^\\s]+)\\s+(?<PID>\\d+)\\s+") {
                $processName = $matches['ImageName']
                $processId = $matches['PID']
                
                # Print the result in the desired format
                "$processName ($processId)"
            }
        }"""   
    
    info(f"Extracting list of active PIDs")

    name_of_output_file = r"pid_data.txt"
    output_file_path = os.path.join(path_to_data_folder, name_of_output_file)

    command_tasklist = f"""
        tasklist | ForEach-Object {{
            if ($_ -match "^\\s*Image Name") {{ return }}
            if ($_ -match "^\\s*$") {{ return }}

            if ($_ -match "^(?<ImageName>[^\\s]+)\\s+(?<PID>\\d+)\\s+") {{
                $processName = $matches['ImageName']
                $processId = $matches['PID']
                
                "$processName, $processId"
            }}
        }} > {output_file_path}
    """

    #print(command_tasklist)

    return_code = execute_terminal_command(command_tasklist)
    if return_code == 0:
        okay(f"Data extracted with success")
        okay(f"Data written to {output_file_path}")
    else:
        warn(f"Execution failed")

def get_dll_data(list_of_pids: List[int]):
    """ Get only the DLL related data
        
        Listdlls.exe <PID> | findstr /i "\\.dll" | ForEach-Object { $_.Split("\\")[-1]} """
    pass

def get_handle_data(list_of_pids: List[int]):
    """ Get only the HANDLE related data
        
        handle.exe -a -p <PID> | findstr /R /C:"Directory" /C:"File" /C:"Key" /C:"Thread" /C:"Process" | ForEach-Object {
            $_ -replace '^\\s*\\w+:\\s*', ''} """
    pass

def read_data():
    """Calls all the get_data related functions"""
    pass

def output_data():
    """Output data as .txt or something"""
    pass

if __name__ == "__main__":
    get_pid_data()
    pass  
