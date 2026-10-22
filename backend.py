import pandas as pd

def load_data(path):
    df = pd.read_csv(path, header=None)
    return df

def preprocess(df, columns):
    df.columns = columns
    df['label'] = df['label'].apply(lambda x: 'Normal' if x == 'normal' else 'Attack')
    return df

def detect_intrusion(df):
    df['prediction'] = df['label']
    return df