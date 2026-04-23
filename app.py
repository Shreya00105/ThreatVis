from backend import load_data, preprocess, detect_intrusion
import streamlit as st
import pandas as pd
import plotly.express as px

# ================= PAGE CONFIG =================
st.set_page_config(page_title="ThreatVision IDS", layout="wide")

df = pd.read_csv(r"C:\Users\HP\Desktop\Shreya\ThreatVis\archive\KDDTest-21.txt", header=None)


columns = [
'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
'root_shell','su_attempted','num_root','num_file_creations','num_shells',
'num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
'dst_host_serror_rate','dst_host_srv_serror_rate','dst_host_rerror_rate',
'dst_host_srv_rerror_rate','label','difficulty_level'
]

df.columns = columns


# ================= PROCESS =================
df['label'] = df['label'].apply(lambda x: 'Normal' if x == 'normal' else 'Attack')

# ================= HEADER =================
st.markdown("<h1 style='text-align: center;'>ThreatVision IDS Dashboard</h1>", unsafe_allow_html=True)
st.markdown("---")

# ================= METRICS =================
total = len(df)
attacks = len(df[df['label'] == 'Attack'])
normal = len(df[df['label'] == 'Normal'])
attack_percent = (attacks / total) * 100

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Traffic", total)
col2.metric("Normal Traffic", normal)
col3.metric("Attack Traffic", attacks)
col4.metric("Attack %", f"{attack_percent:.2f}%")

st.markdown("---")

# ================= CHARTS =================
col1, col2 = st.columns(2)

# Normal vs Attack (Styled Bar)
with col1:
    st.subheader("Traffic Distribution")
    fig1 = px.bar(
        x=['Normal', 'Attack'],
        y=[normal, attacks],
        color=['Normal', 'Attack'],
        color_discrete_map={'Normal': 'green', 'Attack': 'red'}
    )
    st.plotly_chart(fig1, use_container_width=True)

# Busiest Hour
# Simulate realistic traffic variation
import numpy as np

np.random.seed(42)
df['hour'] = np.random.randint(0, 24, size=len(df))

# Create variation (more traffic during peak hours)
df['hour'] = df['hour'].apply(lambda x: x if x < 8 else x + np.random.randint(0,5))

hourly = df.groupby('hour').size().reset_index(name='count')

# Plot clean bar chart (like your 2nd image)
fig2 = px.bar(
    hourly,
    x='hour',
    y='count',
    color='count',
    color_continuous_scale='Oranges'
)

fig2.update_layout(
    xaxis_title="Hour",
    yaxis_title="Traffic Count",
    title="Network Activity: Busiest Hours"
)

st.plotly_chart(fig2, use_container_width=True)



# ================= RECENT TABLE =================
st.subheader("Recent Network Activity")

# Simulated columns
df['Time'] = pd.date_range(start='2024-01-01', periods=len(df), freq='s')
df['Source IP'] = "192.168.1." + (df.index % 255).astype(str)
df['Destination IP'] = "10.0.0." + (df.index % 255).astype(str)
df['Protocol'] = df['protocol_type']

recent = df[['Time','Source IP','Destination IP','Protocol','label']].tail(5)
recent.columns = ['Time','Source IP','Destination IP','Protocol','Status']

st.dataframe(recent, use_container_width=True)

# ================= FOOTER =================
st.markdown("---")
st.markdown("<p style='text-align: center;'>ThreatVision IDS • Intrusion Detection Dashboard</p>", unsafe_allow_html=True)