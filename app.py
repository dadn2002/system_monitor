import streamlit as st
import os

st.title("Graph Analysis Workflow")

st.write("### Display Graph from graphs/graph.html")

html_file_path = "graphs/graph.html"

if os.path.exists(html_file_path):
    with open(html_file_path, "r", encoding="utf-8") as file:
        html_content = file.read()

    st.components.v1.html(html_content, height=600)
else:
    st.error(f"File not found: {html_file_path}. Make sure the file exists.")
