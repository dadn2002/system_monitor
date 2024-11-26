import streamlit as st
import os

st.title("System Monitor Graphs")

graphs_folder = "graphs/"

graph_files = [f for f in os.listdir(graphs_folder) if f.endswith('.html')]

if graph_files:
    selected_graph = st.selectbox("Select a graph to display", graph_files)

    selected_graph_path = os.path.join(graphs_folder, selected_graph)

    with open(selected_graph_path, "r", encoding="utf-8") as file:
        html_content = file.read()

    st.components.v1.html(html_content, height=600)
else:
    st.error(f"No graph files found in the '{graphs_folder}' folder. Please make sure there are HTML files present.")
