import streamlit as st

st.title("Graph Analysis Workflow")

st.write("### Display Graph from HTML File")

uploaded_file = st.file_uploader("Choose a .html file", type="html")

if uploaded_file is not None:
    st.write("### Graph Visualization")
    
    html_content = uploaded_file.read().decode("utf-8")
    st.components.v1.html(html_content, height=600)
else:
    st.write("Please upload a .html file to visualize the graph.")
