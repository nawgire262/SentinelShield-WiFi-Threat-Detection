import streamlit as st


def load_css():

    st.markdown("""

    <style>

    .stApp{
        background:#07111f;
        color:white;
    }

    section[data-testid="stSidebar"]{
        background:#0d1b2a;
    }

    .title{
        font-size:38px;
        font-weight:bold;
        color:white;
    }

    .subtitle{
        color:#9ca3af;
        font-size:18px;
    }

    .card{

        background:#10243d;

        padding:20px;

        border-radius:15px;

        box-shadow:0px 0px 20px rgba(0,255,255,.15);

        margin-bottom:15px;

    }

    .green{

        color:#00ff99;

        font-weight:bold;

    }

    .yellow{

        color:#ffcc00;

        font-weight:bold;

    }

    .red{

        color:#ff4b4b;

        font-weight:bold;

    }

    .metric{

        text-align:center;

        font-size:28px;

        font-weight:bold;

    }

    </style>

    """, unsafe_allow_html=True)