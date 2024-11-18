import subprocess
import argparse
import time
import sys
import os

import matplotlib.pyplot as plt
from pyvis.network import Network
import networkx as nx
import random

import re

from header import *
from extract_data import read_network_data_txt

path_to_graphs_folder = r"graphs"

def setup_arguments_parser() -> None:
    def display_help_and_exit():
        help_message = """
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
        """

        print(help_message)
        sys.exit(0)

    parser = argparse.ArgumentParser(description="Script to handle various flags and exclusions")

    parser.add_argument('-disable_handles'  , action='store_false'  , help="Disable handles processing")
    parser.add_argument('-disable_pids'     , action='store_false'  , help="Disable PIDs processing")
    parser.add_argument('-enable_dlls'      , action='store_true'   , help="Enable DLLs processing")
    parser.add_argument('-disable_networks' , action='store_false'  , help="Disable network processing")
    parser.add_argument('-ignore_list'      , nargs='*'             , help="List of processes to ignore", default=[])

    parser.add_argument('-help'             , action='store_true'   , help="Display commands")
    
    args = parser.parse_args()

    if args.help:
        display_help_and_exit()

    disable_handles     = args.disable_handles
    disable_pids        = args.disable_pids
    enable_dlls         = args.enable_dlls
    disable_networks    = args.disable_networks
    ignore_processes    = args.ignore_list

    result_dict = {
        'disable_handles'   : disable_handles,
        'disable_pids'      : disable_pids,
        'enable_dlls'       : enable_dlls,
        'disable_networks'  : disable_networks,
        'ignore_processes'  : ignore_processes
    }

    # Debug print to check the dictionary
    return result_dict

def read_dataset(ignore_list_of_processes: list) -> list:
    info(f" Reading data files")
    data = read_network_data_txt()

    if not data:
        warn(f"  Could not read data file")
        warn(f" Failure")
        return []

    okay(f"  Managed to read data file")

    #for element in data:
    #    print(element[0], element[1], "\n" + str(element[2]), "\n" + str(element[3]), "\n" + str(element[4]), "\n\n")
    
    # Here we're filtering all elements that refers to a PID of ignored process_name
    # And remove all citations to them from process_handles section of the list
    # debug(f"size before: {len(data)}")
    data = [
        [
            process_name, 
            process_pid, 
            process_dlls, 
            [
                handle for handle in process_handles
                if handle[0] == 'Process' and not any(handle[1].startswith(ignore_that) for ignore_that in ignore_list_of_processes)
            ],
            process_networks
        ]
        for process_name, process_pid, process_dlls, process_handles, process_networks in data
        if not any(process_name.startswith(ignore_that) for ignore_that in ignore_list_of_processes)
    ]
    # debug(f"size after: {len(data)}")

    okay(f"  Success")
    return data

def generate_proper_random_color():
    """ Generate a random hex color."""
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

def generate_random_color(hexcolor=None):
    """ Generate a random hex color close to given hexcolor """
    if hexcolor is None:
        return generate_proper_random_color()
    
    hexcolor = hexcolor.lstrip('#')
    r, g, b = int(hexcolor[0:2], 16), int(hexcolor[2:4], 16), int(hexcolor[4:6], 16)
    
    def clamp(value):
        return max(0, min(255, value))
    
    variation = 25
    new_r = clamp(r + random.randint(-variation, variation))
    new_g = clamp(g + random.randint(-variation, variation))
    new_b = clamp(b + random.randint(-variation, variation))
    
    return "#{:02x}{:02x}{:02x}".format(new_r, new_g, new_b)

def has_edge(edges, node1, node2):
    """Check if an edge exists ???"""
    node1_id = node1['id']
    node2_id = node2['id']
    
    return (node1_id, node2_id) in [(edge['from'], edge['to']) for edge in edges] # or (node2_id, node1_id) in [(edge['from'], edge['to']) for edge in edges]

def generate_directed_pyvis_graph(dataset: list, execution_flags: dict) -> Network:
    """ Create a directed pyvis graph with some parameters/filters
            dataset: contains list of nodes as nodetype
            filters: list of names to filter which nodes/edges are displayed
                        current available filters:
                            enable_pids
                                True  -> Display enable_pids of each process
                                False -> Collapses they all into a single node
                            enable_dlls
                                True  -> Display enable_dlls data of each process
                                False -> Does not display enable_dlls data
                            enable_handles
                                True  -> Display enable_handles data of each process
                                False -> Does not display enable_handles data
                            enable_networks
                                True  -> Display Network data of each process
                                False -> Does not display Network Data
    """

    (enable_handles, enable_pids, enable_dlls, enable_networks, ignore_this_processes) = (
        execution_flags['disable_handles'], 
        execution_flags['disable_pids'], 
        execution_flags['enable_dlls'], 
        execution_flags['disable_networks'], 
        execution_flags['ignore_processes']
    )
    info(" Generating directed pyvis graph of data")
    info("  Filters enabled")
    info(f"   Pids      : {enable_pids}")
    info(f"   Dlls      : {enable_dlls}")
    info(f"   Handles   : {enable_handles}")
    info(f"   Networks  : {enable_networks}")

    nodes_to_add                = []
    root_nodes_to_add           = []
    dlls_nodes_to_add           = [] # More organized or just a dumbshit idea?
    #handles                    = [] # They are edges only
    #networks                   = [] # They are edges only
    edges_to_add                = []

    dlls_node_color             = '#222222'
    networks_node_color         = '#E7E7E7'
    networks_node_color_remote  = '#A1A1A1'

    root_nodes_size             = 40
    process_node_size           = 20
    dlls_node_size              = 15
    handles_node_size           = 15
    networks_node_size          = 15
    unknown_node_size           = 10

    root_edge_process_color     = '#EBE4D6' 
    process_edge_dll_color      = '#FFFFFF' # Setting as white so that i remember to change it in the future
    process_edge_handle_color   = '#FF6666'
    process_edge_network_color  = '#FFDC70'

    net = Network(height='1000px', width='100%', bgcolor='#222222', font_color='white', directed=True) # Forgot the directed flag
    net.force_atlas_2based()
    net.set_options("""
    {
        "physics": {
            "enabled": true,
            "barnesHut": {
                "gravitationalConstant" : -20000,
                "centralGravity"        : 0.7,
                "springLength"          : 100,
                "springConstant"        : 0.05
            },
            "stabilization": {
                "enabled"               : true,
                "iterations"            : 500,
                "updateInterval"        : 25
            }
        }
    }
    """) 
    # Placing here the funnier values before i mess with them:
    # gravitationalConstant -20000
    # centralGravity        0.7
    # sprintLenght          100
    # springConstant        0.05
    # enabled               true (Obviously)
    # iterations            500
    # updateInterval        25

    #----------------------------------Add nodes to nodes_to_add list----------------------------------#

    for item in dataset:
        process_name, process_pid, process_dlls, process_handles, process_networks = item
        #print(process_name, process_pid)
        #print(item)
        #wait()

        # Adding the process nodes
        nodes_to_add.append({
            'id'    : process_pid, 
            'label' : str(process_pid), 
            'title' : process_name,
            'type'  : 'process',
            'color' : '#ffffff', # Default color, will be replaced 
            'size'  : process_node_size
        })

        # Adding the root nodes
        if not any(node['id'] == process_name for node in root_nodes_to_add):
            root_nodes_to_add.append({
                'id'    : process_name, 
                'label' : process_name.replace(".exe", ""), 
                'title' : process_name.replace(".exe", ""),
                'type'  : 'root',
                'color' : '#ffffff', # Default color, will be replaced 
                'size'  : root_nodes_size
            })

        # Adding the dlls nodes and edges
        if enable_dlls:
            if process_dlls:
                #print(process_name)
                for i, dlls in enumerate(process_dlls):
                    if dlls in dlls_nodes_to_add:
                        continue
                    #print(i, dlls)
                    # Add the proper dll node
                    dlls_nodes_to_add.append({
                        'id'    : dlls, 
                        'label' : dlls.replace(".dll", ""), 
                        'title' : dlls.replace(".dll", ""), 
                        'type'  : 'dll',
                        'color' : dlls_node_color, 
                        'size'  : dlls_node_size
                    })
                    # Add the edge from process_node to dll_node
                    edges_to_add.append({
                        'from'  : process_pid,              # Source processs node ID
                        'to'    : dlls,                     # Target dll node ID
                        'color' : process_edge_dll_color,   # Optional: Edge color
                        'width' : 1                         # Optional: Edge width
                    })

                #wait()
    
    # Adding the handles nodes and edges (They must be plotted after the pids and dlls, some processes have handles to dlls so)
    if enable_handles:
        pattern = r'\((.*?)\)'
        for item in dataset:
            process_name, process_pid, _ , process_handles, _ = item
            if process_handles:
                #print(process_name)
                for i, handles in enumerate(process_handles):
                    #print("\n" + str(i), handles)
                    handle_type, handle_to, (_) = handles

                    match = re.search(pattern, handle_to)

                    if not match:
                        warn("Malformed handle found:")
                        warn(f"{handle_to}")
                        continue

                    if not match.group(1).isdigit:
                        continue

                    handle_to = int(match.group(1))
                    
                    if handle_type == 'Thread':
                        #warn(f"Type of handle: {handle_type} is not supported yet")
                        #print(f"{handle_to} -> {_}")
                        continue

                    if handle_type == 'Process':
                        #print(f"\n{str(i)}: {handle_type} {process_pid} -> {handle_to} | {_}")
                        #okay(f"{handle_type} handle found")
                        pass

                    # Checking if process exists (If he's really present in nodes_to_add)
                    if not any(process_node['id'] == handle_to for process_node in nodes_to_add):
                        warn("Unknown process node")
                        print(f" -> {handle_to}?")
                        nodes_to_add.append({
                            'id'    : handle_to, 
                            'label' : str(handle_to),
                            'title' : 'Unknown',
                            'type'  : 'process',
                            'color' : '#111111',
                            'size'  : process_node_size
                        })
                        #continue

                    edges_to_add.append({
                        'from'  : process_pid,                  # Source processs node ID
                        'to'    : handle_to,                    # Target dll node ID
                        'color' : process_edge_handle_color,    # Optional: Edge color
                        'width' : 1                             # Optional: Edge width
                    })

                #wait()
    
    if enable_networks:
        pattern = r'\((.*?)\)'
        for item in dataset:
            process_name, process_pid, _ , _, process_networks = item

            #print(process_name, process_pid, process_networks)
            
            if not process_networks:
                continue

            for process_network_data in process_networks:

                connection_type, local_ip, remote_ip, connection_status, _ = process_network_data

                # Connection is invalid/unknown or whatever
                if connection_status == "N/A":
                    #continue
                    pass

                if remote_ip == "0.0.0.0:0" or remote_ip == ":":
                    remote_ip = ""

                #print(process_name, process_pid, connection_type, local_ip, remote_ip, connection_status)

                nodes_to_add.append({
                    'id'    : str(local_ip),
                    'label' : str(local_ip),
                    'title' : f"{connection_type} {local_ip} LOCAL",
                    'type'  : 'network',
                    'color' : networks_node_color,
                    'size'  : networks_node_size
                })

                #Reformat the label/title of nodes
                for string, protocol in [["[::]:", "IPv6"], ["0.0.0.0:", "IPv4"]]:
                    if string in local_ip:
                        nodes_to_add[-1]['label'] = f"{local_ip.replace(string, "")}"
                        nodes_to_add[-1]['title'] = f"{connection_type} {protocol} LOCAL"

                #Add as a generic network connection, then
                #check if has format :1234 (Port IPv6) or
                #check if has format 0.0.0.0:123123 (Port IPv4)
                #If not, its a normal connection 192.168.0.1:8080
                edges_to_add.append({
                    'from'  : local_ip,                     # Source network node ID
                    'to'    : process_pid,                  # Target process node ID
                    'color' : process_edge_network_color,   # Optional: Edge color
                    'width' : 1                             # Optional: Edge width
                })

                #If its not a port listening or a loopback ip, its also sending packages from it
                if "[::]:" not in local_ip and "0.0.0.0:" not in local_ip:
                    if "[::1]:" not in local_ip and "127.0.0.1:" not in local_ip:
                        edges_to_add[-1]['arrows'] = {'to': True, 'from': True}    # This makes the edge bidirectional

                if remote_ip:
                    nodes_to_add.append({
                        'id'    : str(remote_ip),
                        'label' : str(remote_ip),
                        'title' : f"{connection_type} {remote_ip} REMOTE",
                        'type'  : 'network',
                        'color' : networks_node_color_remote,
                        'size'  : networks_node_size
                    })

                    #Reformat the label/title of nodes
                    for string, protocol in [["[::]:", "IPv6"], ["0.0.0.0:", "IPv4"]]:
                        if string in remote_ip:
                            nodes_to_add[-1]['label'] = f"{remote_ip.replace(string, "")}"
                            nodes_to_add[-1]['title'] = f"{connection_type} {protocol} REMOTE"
                            
                    edges_to_add.append({
                        'from'  : remote_ip,                    # Source network node ID
                        'to'    : process_pid,                  # Target process node ID
                        'color' : process_edge_network_color,   # Optional: Edge color
                        'width' : 1                             # Optional: Edge width
                    })

                    if "[::]:" not in remote_ip and "0.0.0.0:" not in remote_ip:
                        if "[::1]:" not in remote_ip and "127.0.0.1:" not in remote_ip:
                            edges_to_add[-1]['arrows'] = {'to': True, 'from': True}    # This makes the edge bidirectional

    #print(len(root_nodes_to_add))
    #for node in root_nodes_to_add:
    #    print(node)
    #    print(node["title"] if "title" in node else None)
    #wait()

    #----------------------------------Add edges to edges_to_add list----------------------------------#

    # Adding the edges from root_nodes to process_nodes
    for process_node in nodes_to_add:
        for root_node in root_nodes_to_add:
            if process_node["title"] == root_node["id"]:
                #print(process_node, "\n", root_node, "\n")
                edges_to_add.append({
                    'from'  : root_node["id"],      
                    'to'    : process_node["id"],   
                    'color' : root_edge_process_color,            
                    'width' : 1                     
                })

    #for item in dataset:
    #    pass

    #-----------------------------------Apply color mapping to nodes-----------------------------------#
    for root_node in root_nodes_to_add:
        root_node['color'] = generate_random_color()
        for process_node in nodes_to_add:
            #for edge in edges_to_add:
            #    print(edge)
            if has_edge(edges_to_add, root_node, process_node):
                #print(f"Edge: {root_node['id']} {process_node['id']}")
                process_node['color'] = generate_random_color(root_node['color'])
    #-----------------------------------Apply color mapping to edges-----------------------------------#

    #----------------------------Add nodes from nodes_to_add to pyvis graph----------------------------#
    for node in nodes_to_add:
        net.add_node(
            node['id'],
            label   = node['label'],
            title   = node['title'],
            type    = node['type'],
            color   = node.get('color', '#000000'),  
            size    = node.get('size', unknown_node_size)            
        )

    #--------------------------Add nodes from root_nodes_to_add to pyvis graph-------------------------#
    for node in root_nodes_to_add:
        net.add_node(
            node['id'],
            label   = node['label'],
            title   = node['title'],
            type    = node['type'],
            color   = node.get('color', '#000000'),  
            size    = node.get('size', unknown_node_size)            
        )

    #--------------------------Add nodes from dlls_nodes_to_add to pyvis graph-------------------------#

    if dlls_nodes_to_add:
        for node in dlls_nodes_to_add:
            net.add_node(
                node['id'],
                label   = node['label'],
                title   = node['title'],
                type    = node['type'],
                color   = node.get('color', '#000000'),  
                size    = node.get('size', unknown_node_size)            
            )

    #----------------------------Add edges from edges_to_add to pyvis graph----------------------------#
    for edge in edges_to_add:
        edge_params = {
            'color': edge.get('color', '#000000'),
            'width': edge.get('width', 1)
        }
        if 'arrows' in edge:
            edge_params['arrows'] = edge['arrows']
    
        net.add_edge(
            edge['from'],
            edge['to'],
            **edge_params
        )
    
    #------------------------------------Apply pids filters to nodes-----------------------------------#

    #------------------------------------Apply pids filters to edges-----------------------------------#

    #--------------------------------------------Save graph--------------------------------------------#
    net.write_html(f'{path_to_graphs_folder}//graph.html')
    okay("  Success")
    return net # For subgraph generation or something

def generate_graphs_main(execution_flags: dict) -> None:
    data = read_dataset(ignore_list_of_processes=execution_flags['ignore_processes'])
    #for node in data:
    #    print(node)
    generate_directed_pyvis_graph(data, execution_flags=execution_flags)

if __name__ == "__main__":
    execution_flags = setup_arguments_parser()
    os.system("cls")
    info(f"Running code in terminal")
    generate_graphs_main(execution_flags)