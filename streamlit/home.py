import streamlit as st
import pandas as pd
import numpy as np
import pickle

knn = pickle.load(open('../knn.pkl','rb'))
lin = pickle.load(open('../lin.pkl','rb'))
log = pickle.load(open('../log.pkl','rb'))

st.title("PhiTector - Detect Phishing Links")
st.subheader("Enter a URL below and check possibility of it being a phishing link")

url = st.text_input(label='URL')

st.subheader("KNN Accuracy")
#Code to insert 

