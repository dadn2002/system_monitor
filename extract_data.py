
import subprocess
import time
import sys
import ast
import os
import re
from header import *

path_to_data_folder         = "data"

name_of_pid_data_file       = "pid_data.txt"
output_pid_data_path        = os.path.join(path_to_data_folder, name_of_pid_data_file)

name_of_dll_data_file       = "dll_data.txt"
output_dll_data_path        = os.path.join(path_to_data_folder, name_of_dll_data_file)

name_of_handle_data_file    = "handle_data.txt"
output_handle_data_path     = os.path.join(path_to_data_folder, name_of_handle_data_file)

name_of_network_data_file   = "network_data.txt"
output_network_data_path    = os.path.join(path_to_data_folder, name_of_network_data_file)

path_to_sysutils_folder     = "sysutils"
spinner                     = ["|", "/", "-", "\\"]

def wait(): 
    debug("Stop")
    wait = input('Press enter to continue...')

def convert_csv_content_to_list(file_path):
    """Read the content of a .txt file and return it as a list of lines."""
    try:
        with open(file_path, 'r', encoding='utf-16') as file:
            lines = file.readlines()
    except UnicodeError:
        # If UTF-16 fails, fall back to UTF-8 or another encoding
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
    # Strip newline characters and split on comma
    return [line.strip().split(', ') for line in lines]

def convert_csv_complex_content_to_list(file_path):
    process_data = []

    try:
        with open(file_path, 'r', encoding='utf-16') as file:
            lines = file.readlines()
    except UnicodeError:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

    for line in lines:
        line = line.strip()  # Remove any leading/trailing whitespace
        if not line or line.startswith("Process Name"):
            continue

        # Split the line by commas (but only the first two commas)
        parts = line.split(',', 2)

        if len(parts) < 3:
            warn(f" Malformed line: {parts}")
            continue  # Skip lines that don't have enough parts

        process_name = parts[0].strip()
        pid = int(parts[1].strip())
        dlls = [dll.strip().replace('"', "") for dll in parts[2].split(';')]

        process_data.append([process_name, pid, dlls])

    return process_data

def parse_connections(lines):
    connections = []
    pattern_pids = re.compile(r'(\w+)\s+([\[\]0-9a-fA-F:.]+:\d+)\s+([\[\]0-9a-fA-F:.]:\d|[:]+)\s*(\w+)?\s+(\d+)')

    for line in lines:
        match = pattern_pids.match(line.strip())
        if match:
            connections.append([match.group(1), match.group(2), match.group(3), match.group(4) if match.group(4) else "N/A", int(match.group(5))])
            #connection = {
            #    "Protocol": match.group(1),
            #    "Local Address": match.group(2),
            #    "Foreign Address": match.group(3),
            #    "State": match.group(4) if match.group(4) else "N/A",  # Handle missing state
            #    "PID": int(match.group(5))
            #}
            #connections.append(connection)
    return connections

def execute_terminal_command(command: str, return_output: bool = False, name: str = 'powershell'):
    """Execute a str as a command"""
    if name.lower() == 'cmd':
        process = subprocess.run(command, shell=True, text=True, capture_output=True)
    elif name.lower() == 'powershell':
        process = subprocess.run(['powershell', '-Command', command], text=True, capture_output=True)
    else:
        raise ValueError("Invalid terminal name. Use 'cmd' or 'powershell'.")

    if not return_output:
        return process.returncode
    else:
        return process.stdout, process.stderr

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
    
    #----------------Extracting the data with tasklist----------------#
    info(f" Extracting list of active PIDs")

    command_tasklist = f"""
        tasklist | ForEach-Object {{
            if ($_ -match "^\\s*Image Name") {{ return }}
            if ($_ -match "^\\s*$") {{ return }}

            if ($_ -match "^(?<ImageName>[^\\s]+)\\s+(?<PID>\\d+)\\s+") {{
                $processName = $matches['ImageName']
                $processId = $matches['PID']
                
                "$processName, $processId"
            }}
        }} > {output_pid_data_path}
    """

    #print(command_tasklist)
    return_code = execute_terminal_command(command_tasklist)
    if return_code == 0:
        okay(f"  Data extracted with success")
        okay(f"  Data written to {output_pid_data_path}")
    else:
        warn(f"  Failure")
        return

    okay(f"  Success")

def read_pid_data_txt():
    """ Prepare the list of PIDs to return """
    sorted_converted_data = []

    info(f" Reading data of {output_pid_data_path}")
    data = convert_csv_content_to_list(output_pid_data_path)
    if not data:
        warn("  Failed to open file")
        return sorted_converted_data
    okay("  Success")
    
    convert_pids_to_int_data = [[item[0], int(item[1])] for item in data]
    #print(convert_pids_to_int_data)
    sorted_converted_data = sorted(convert_pids_to_int_data, key=lambda x: x[1])

    return sorted_converted_data

def get_dll_data(list_of_pids: list):
    """ Get only the DLL related data  
        Listdlls.exe <PID> | findstr /i "\\.dll" | ForEach-Object { $_.Split("\\")[-1]} 
    """

    #----------------Extracting the dll data----------------#

    info(f" Extracting DLL related data of PIDs")
    info(f"  Generating base data")
    info(f"  (It may take a while)")

    start_time = time.time()
    #print(f"\rProcessing PID {pid} ({i}/{len(list_of_pids)}) {spinner[i % len(spinner)]}", end="")
    
    command_listdlls = r"""
        powershell -ExecutionPolicy Bypass -File .\command_listdlls.ps1
    """

    ret_value = execute_terminal_command(command_listdlls)
    if ret_value:
        warn(f"   Failed generating DLL data!")
        return
    okay(f"   Created data file: {output_dll_data_path}")
    info(f"  Starting to format the data file")

    #----------------Accessing and formatting the generated data----------------#

    with open(output_dll_data_path, 'r', encoding='utf-16') as file:
        lines_of_data = file.readlines()

    lines_of_data = [line[:-1].replace("\n", "") for line in lines_of_data][3:]
    lines_of_data = [line for line in lines_of_data if line] # line[0].isdigit() check if is a PID row or not

    #for i, line in enumerate(lines_of_data):
    #    print(i, line)

    list_pids_and_dlls = []
    current_pid = None
    current_dlls = []
    for line in lines_of_data:
        # Check if the line starts with a PID (one or more digits)
        match = re.match(r'^\d+', line)
        if match:
            if current_pid:
                list_pids_and_dlls.append((current_pid, current_dlls))
            
            # Start tracking a new PID
            current_pid = match.group(0)
            current_dlls = []

            line = line[len(current_pid):].strip()

        if current_pid:
            dlls_in_line = line.split(", ")
            current_dlls.extend([dll.strip() for dll in dlls_in_line if dll.strip()])

    if current_pid:
        list_pids_and_dlls.append((current_pid, current_dlls))
            
    #for element in list_pids_and_dlls:
    #    print(element)

    merged_list = []
    match_found = False
    for process_name, process_pid in list_of_pids:
        for pid, dlls in list_pids_and_dlls:
            pid = int(pid)
            if pid == process_pid:
                merged_list.append([process_name, pid, dlls])
                match_found = True
                break
        if not match_found:
            merged_list.append([process_name, process_pid, []])
        match_found = False

    amount_of_discarted_pids = len(list_pids_and_dlls) - len(merged_list)
    if amount_of_discarted_pids > 0:
        warn(f"   Number of ignored PIDs: {amount_of_discarted_pids}/{len(list_pids_and_dlls)} of max {len(list_of_pids)}")

    #for element in merged_list:
    #    print(element)

    merged_list = sorted(merged_list, key=lambda x: x[1])

    #debug("Merged_list")
    #for data in merged_list:
    #    print(data)
    #wait()

    #----------------Saving the data in the data file----------------#

    with open(output_dll_data_path, 'w', newline='') as file:
        file.write('Process Name,PID,DLLs\n')
        
        for i, (process_name, pid, dlls) in enumerate(merged_list):
            print(f"\rProcessing PID {pid} ({i}/{len(merged_list)}) {spinner[i % len(spinner)]}", end="")
            # It'll probably be way to fast
            dlls_str = '; '.join(dlls)
            file.write(f'{process_name},{pid},"{dlls_str}"\n')
    
    okay(f"\r[+]    Formatted data written to {output_dll_data_path}")

    end_time = time.time()
    okay(f"  Extracted data with success after: {end_time-start_time:.4f} seconds")

    okay(f"  Success")

    return output_dll_data_path

def read_dll_data_txt():
    """ Prepare the list of DDLs to return """

    info(f" Reading data of {output_dll_data_path}")
    data = convert_csv_complex_content_to_list(output_dll_data_path)
    if not data:
        warn("  Failed to open file")
        return []
    okay("  Success")
    
    data = sorted(data, key=lambda x: x[1])
    #for element in data:
    #   print(element, "\n")

    return data

def get_handle_data(list_of_pids_with_dll: list):
    """ Get only the HANDLE related data
        handle.exe -a -p <PID> | findstr /R /C:"Directory" /C:"File" /C:"Thread" /C:"Process" | ForEach-Object {
            $_ -replace '^\\s*\\w+:\\s*', ''} 
    """
    
    #----------------Extracting the data with handle.exe----------------#
    info(f" Extracting list of handles of active PIDs")
    info(f"  Generating base data")
    info(f"  (It may take a while)")

    command_handleexe = f"""
        handle.exe -a | findstr /I /R /C:"Thread" /C:"Process" /C:"pid:" | ForEach-Object {{
            if ($_ -match 'pid:') {{
                $_
            }} else {{
                $_ -replace '^\\s*\\w+:\\s*', ''
            }}
        }} > {output_handle_data_path}
    """

    return_code = execute_terminal_command(command_handleexe)
    if return_code == 0:
        okay(f"   Data extracted with success")
        okay(f"   Data written to {output_handle_data_path}")
    else:
        warn(f"   Execution failed")
        return
         
    wait()
    #----------------Formatting the datafile----------------#

    info(f"  Filtering and formatting the data obtained")
    with open(output_handle_data_path, 'r', encoding='utf-16') as file:
        lines_of_data = file.readlines()

    formatted_data          = []
    handles_to_insert_data  = []
    pattern_pids            = r"^(.?)\s+pid:\s(\d+)\s*(.*)$"
    pattern_handles         = r"(\w+)\s+([\w.]+(?:\(\d+\))?)\s*(?::\s*(.*))?" #r"(\S+)\s+(\S+)\s+(\S+)?"
    match_found             = False
    ignore_next_handles     = False

    for line in lines_of_data:
        line = line.strip()
        if not line or 'Error Opening' in line or 'Nonexistent' in line:
            continue
        
        #print(line)

        #--------------check if start capturing pid handles--------------#
        if 'pid:' in line:
            #wait()
            match = re.match(pattern_pids, line)

            ignore_next_handles = False
            if not match:
                warn(f"   Malformed PID line,    ignoring PIDs: {line}")
                #print(line)
                ignore_next_handles = True
                continue

            process_name = match.group(1)           # Captures the process name
            pid = match.group(2)                    # Captures the PID            
            handles_to_insert_data.append([process_name, int(pid), []])
        #--------------append line to handles_to_insert--------------#
        else:
            if ignore_next_handles:
                continue
            #debug("Line:")
            #print(line) 
            match = re.match(pattern_handles, line)

            if not match:
                warn(f"   Malformed HANDLE line, ignoring handle: {line}")
                #print(line)
                continue

            handle_type = match.group(1).strip()

            if handle_type not in ['Process', "Thread"]:
                warn(f"   Unknown HANDLE type,   ignoring handle: {line}")
                #print(line)
                continue

            process_name = match.group(2).strip()
            last_part = match.group(3).strip() if match.group(3) else None

            
            handle_data = [handle_type, process_name, last_part]
            #debug("Pattern match data")
            #print(handle_data)
            handles_to_insert_data[-1][2].append(handle_data)

    handles_to_insert_data = sorted(handles_to_insert_data, key=lambda x: x[1])

    #for data in handles_to_insert_data:
    #    print(data)
    #wait()

    #----------------match the data with the list_of_pids_with_dll----------------#
    for dll_data in list_of_pids_with_dll:
        found_match = False
        for handles_data in handles_to_insert_data:
            if dll_data[1] == handles_data[1]:
                #debug(f"PID match ({dll_data[1]}), ({handles_data[0]}), ({handles_data[1]}), ({len(handles_data[2])})")
                formatted_data.append([dll_data[0], dll_data[1], dll_data[2] if dll_data[2] else [], handles_data[2]]) # append, not equal... stupid
                #print(formatted_data[-1])
                found_match = True
                break
        if not found_match: # append if not found handle data
            formatted_data.append([dll_data[0], dll_data[1], dll_data[2] if dll_data[2] else [], []])

    #wait()
    #for data in formatted_data:
    #    print(data)
    
    ignored_any_pid = False
    info("  PIDs ignored (Spawned after tasklist and listdlls execution)")
    for process_name, pid, _ in list_of_pids_with_dll:
        missing_pid = True
        for _, formatted_pid, _, ___ in formatted_data:
            #if process_name == 'Registry':
                #print(process_name, pid, , _, formatted_pid)
            if pid == formatted_pid:
                missing_pid = False
                break
        if missing_pid:
            ignored_any_pid = True
            info(f"Ignored PID: {process_name}({pid})")
    if not ignored_any_pid:
        okay("   No detected PID was ignored")

    #----------------Saving the data in the data file----------------#
    with open(output_handle_data_path, 'w', newline='') as file:
        file.write('Process Name, PID, DLLs, Handles_List\n')

        for i, element in enumerate(formatted_data):
            if len(element) >= 4:
                file.write(f'{element[0]},{element[1]},{element[2]},{element[3]}\n')
    okay(f"\r[+]   Formatted data written to {output_handle_data_path}")
    okay(f"  Success")

def read_handle_data_txt():
    """ Read the Handle data file and return a list """

    info(f" Reading data of {output_handle_data_path}")
    with open(output_handle_data_path, 'r', encoding='utf-8') as file:
        data = file.readlines()
    if not data:
        warn("  Failed to open file")
        return []
    okay("  Success")
    
    cleaned_data = []

    data = data[1:]

    for element in data:
        element = element.replace("\n", "")
        temporary_data = element.split(",", 2)
        data = temporary_data[2].split("],[")
        data[0] = ast.literal_eval(data[0]+"]")
        if data[0] == ['']:
            data[0] = []
        data[1] = ast.literal_eval("["+data[1])
        for handles in data[1]:
            if len(handles) == 3:
                if handles[2] and handles[2].isdigit():
                    handles[2] = int(handles[2])
        #print(temporary_data[0], "\n", temporary_data[1], "\n", data[0], "\n", data[1])
        #wait()
        cleaned_data.append([temporary_data[0], int(temporary_data[1]), data[0], data[1]])
        
    return cleaned_data

def get_network_data(list_of_pids_dlls_handles: list):
    """ Get the Network data of PIDs that are running
        
        basic usage netstat
        # use arp -a, ipconfig for debugging if needed

        netstat -ano
    """   
    
    #----------------Extracting the data with netstat----------------#
    info(f" Extracting network data of active PIDs")
    info(f"  Generating base data")

    command_tasklist = f"""
        netstat -ano > {output_network_data_path}
    """

    #print(command_tasklist)
    return_code = execute_terminal_command(command_tasklist)
    if return_code == 0:
        okay(f"   Data extracted with success")
        okay(f"   Data written to {output_network_data_path}")
    else:
        warn(f"   Execution failed")
        return

    #----------------Formatting the datafile----------------#
    info(f"  Formatting data from {output_network_data_path}")

    with open(output_network_data_path, 'r', encoding='utf-16') as file:
        lines_of_data = file.readlines()

    #Proto  LocalAddress  ForeignAddress  State  PID
    lines_of_data = lines_of_data[4:] # line3 contains columns names

    lines_of_data = [line.replace("\n", "") for line in lines_of_data]

    parsed_connections = parse_connections(lines_of_data)

    #for element in list_of_pids_dlls_handles:
    #    print(element, "\n")
    #wait()

    if type(parsed_connections) is not list:
        warn(f"   Type of data obtained is not LIST, major error: {type(parsed_connections)}")
        #print(type(parsed_connections))
        wait()
        return []
    
    #for element in parsed_connections:
    #    print(element)
    #wait()

    list_of_pids_dlls_handles_network = []

    for process_name, process_pid, process_dlls, process_handles in list_of_pids_dlls_handles:
        list_of_networks_ips_connected = []
        for data_of_network in parsed_connections:
            if data_of_network[-1] == process_pid:
                #print("MATCH")
                #print(process_name, process_pid, data_of_network)
                list_of_networks_ips_connected.append(data_of_network)
                #break
        if list_of_networks_ips_connected:
            list_of_pids_dlls_handles_network.append([process_name, process_pid, process_dlls, process_handles, list_of_networks_ips_connected])
        else:
            list_of_pids_dlls_handles_network.append([process_name, process_pid, process_dlls, process_handles, []])

    
    #----------------Saving the data in the data file----------------#

    #debug("List network data")    
    #for data in list_of_pids_dlls_handles_network:
    #    print(data, "\n")

    with open(output_network_data_path, 'w', newline='') as file:
        file.write('Process Name, PID, DLLs, Handles_List, Network_data\n')

        for i, element in enumerate(list_of_pids_dlls_handles_network):
            if len(element) >= 4:
                file.write(f'{element[0]},{element[1]},{element[2]},{element[3]},{element[4]}\n')
    okay(f"\r[+]    Formatted data written to {output_network_data_path}")
    okay(f"  Success")

def read_network_data_txt():
    """ Prepare the list of network data to return """
    network_data_list = []  # Store all network data here
    
    with open(output_network_data_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or "Process Name, PID, DLLs, Handles_List, Network_data" in line:
                continue
            
            try:
                process_info, remaining = line.split(',', 2)[:2], line.split(',', 2)[2]
                process_name = process_info[0]
                pid = int(process_info[1])

                first_bracket = remaining.find('[')
                last_bracket = remaining.rfind(']')

                dlls_handles_network_str = remaining[first_bracket:last_bracket+1]
                
                dlls_handles_network = ast.literal_eval(dlls_handles_network_str)
                
                dlls = [element.replace(",", "") for element in dlls_handles_network[0]]
                handles = dlls_handles_network[1]
                network_data = dlls_handles_network[2]

                network_data_list.append([process_name, pid, dlls, handles, network_data])

            except (ValueError, SyntaxError, IndexError) as e:
                print(f"Error processing line: {line}")
                print(f"Error: {e}")
    
    return network_data_list

def read_data():
    """Calls all the get_data related functions"""
    pass

def output_data():
    """Output data as .txt or something"""
    pass

if __name__ == "__main__":
    os.system("cls")
    info(f"Running code in terminal")
    
    get_pid_data()
    list_of_pids = sorted(read_pid_data_txt(), key=lambda x: x[1])
    #print(len(list_of_pids))
    #for element in list_of_pids:
    #    print(element[0], element[1])

    get_dll_data(list_of_pids)
    list_of_pids_with_dll = sorted(read_dll_data_txt(), key=lambda x: x[1])
    #print(len(list_of_pids_with_dll))
    #for element in list_of_pids_with_dll:
    #    print(element[0], element[1])

    get_handle_data(list_of_pids_with_dll)
    list_of_pids_dlls_handles = read_handle_data_txt()
    #print(len(list_of_pids_dlls_handles))
    #for element in list_of_pids_dlls_handles:
    #    print(element[0], element[1])

    get_network_data(list_of_pids_dlls_handles)
    #list_of_pids_dlls_handles_network = read_network_data_txt()
    #for element in list_of_pids_dlls_handles_network:
    #    print(element[0], element[1], "\n" + str(element[2]), "\n" + str(element[3]), "\n" + str(element[4]), "\n\n")
    okay("Execution completed! Closing program.")
    pass