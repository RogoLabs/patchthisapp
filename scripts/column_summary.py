import pandas as pd

def main():
    df = pd.read_csv('data/data.csv')
    print('--- Vendor ---')
    print('Non-empty count:', df['Vendor'].notna().sum())
    print('Unique values:', df['Vendor'].nunique())
    print('Top 10 most common:')
    print(df['Vendor'].value_counts().head(10))
    print('\n--- Affected Products ---')
    print('Non-empty count:', df['Affected Products'].notna().sum())
    print('Unique values:', df['Affected Products'].nunique())
    print('Top 10 most common:')
    print(df['Affected Products'].value_counts().head(10))
    print('\n--- CVSS_Vector ---')
    print('Non-empty count:', df['CVSS_Vector'].notna().sum())
    print('Unique values:', df['CVSS_Vector'].nunique())
    print('Value counts:')
    print(df['CVSS_Vector'].value_counts())

if __name__ == "__main__":
    main()
