import pandas as pd
import sys

def main():
    try:
        df = pd.read_csv('data/data.csv')
    except FileNotFoundError:
        print("Error: data/data.csv not found. Run patchthisapp.py first.")
        sys.exit(1)

    for col in ['Vendor', 'Affected Products', 'CVSS_Vector']:
        print(f'\n--- {col} ---')
        if col not in df.columns:
            print(f'Column "{col}" not found in data. Available: {list(df.columns)}')
            continue
        print('Non-empty count:', df[col].notna().sum())
        print('Unique values:', df[col].nunique())
        print('Top 10 most common:')
        print(df[col].value_counts().head(10))

if __name__ == "__main__":
    main()
