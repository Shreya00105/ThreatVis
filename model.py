import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


df = pd.read_csv(r"C:\Users\HP\Desktop\Shreya\SecuVis\archive\KDDTest-21.txt", header=None)

print("Dataset Loaded Successfully")
print("Shape:", df.shape)


print("\nFirst 5 Rows:")
print(df.head())


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


df['attack_type'] = df['label']

df['label'] = df['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')

print("\nLabel Distribution:")
print(df['label'].value_counts())


plt.figure()
sns.countplot(x='label', data=df)
plt.title("Normal vs Attack Traffic")
plt.xlabel("Traffic Type")
plt.ylabel("Count")
plt.show()


plt.figure()
top_attacks = df['attack_type'].value_counts().head(5)
top_attacks.plot(kind='bar')
plt.title("Top 5 Attack Types")
plt.xlabel("Attack Type")
plt.ylabel("Count")
plt.show()


plt.figure()
sns.countplot(x='protocol_type', hue='label', data=df)
plt.title("Protocol vs Traffic Type")
plt.xlabel("Protocol Type")
plt.ylabel("Count")
plt.show()


plt.figure()
sns.histplot(df['src_bytes'], bins=50, kde=True)
plt.title("Source Bytes Distribution")
plt.xlabel("Source Bytes")
plt.ylabel("Frequency")
plt.show()



def detect_intrusion(row):
    if row['src_bytes'] > 10000:
        return "suspicious"
    else:
        return "normal"

df['detection'] = df.apply(detect_intrusion, axis=1)

print("\nDetection Output:")
print(df['detection'].value_counts())

print("\nFinal Summary:")
print("Total Records:", len(df))
print("Attack Records:", len(df[df['label'] == 'attack']))
print("Normal Records:", len(df[df['label'] == 'normal']))
