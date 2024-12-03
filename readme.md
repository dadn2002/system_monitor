
## Dependencies
- Sysinternals https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
- Python

## Usage
```bash
python extract_data.py
```
For data collection, need some programs from Sysinternals to work.
Generate `data/network_data.txt` and subproducts.

```bash
python generate_data.py
```
Graph creation, uses `data/network_data.txt` to create `graphs/graph.html`.

### Flag `-help` to Display Commands:
```
Usage: generate_graphs.py [OPTIONS]
    Options:
    -help                  Display this help message and exit.
    -disable_handles       Disable handles processing.
    -disable_pids          Disable PIDs processing.
    -enable_dlls           Enable DLLs processing.
    -disable_networks      Disable network processing.
    -ignore_list           List of processes to ignore (space separated).
    Example:
    python generate_graphs.py -disable_handles -ignore_list lsass svchost
```
