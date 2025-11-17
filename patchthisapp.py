# patchthisapp.py
# Modernized: pathlib, type hints, argparse, modularization, logging, __main__ guard, file checks

from pathlib import Path
import argparse
import json
import logging
import pandas as pd
from typing import List, Dict, Tuple, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_csv(path: Path, **kwargs) -> pd.DataFrame:
    """Load CSV file with error handling."""
    if not path.exists():
        logging.error(f"Missing file: {path}")
        return pd.DataFrame()
    
    try:
        return pd.read_csv(path, **kwargs)
    except (pd.errors.EmptyDataError, pd.errors.ParserError) as e:
        logging.error(f"Error reading CSV file {path}: {e}")
        return pd.DataFrame()
    except Exception as e:
        logging.error(f"Unexpected error reading {path}: {e}")
        return pd.DataFrame()

def load_metasploit_nuclei(metasploit_path: Path, nuclei_path: Path) -> pd.DataFrame:
    """Load and combine Metasploit and Nuclei CVE data."""
    columns = ['CVE']
    metasploit_df = load_csv(metasploit_path, header=None, names=columns)
    nuclei_df = load_csv(nuclei_path, header=None, names=columns)
    
    if metasploit_df.empty and nuclei_df.empty:
        logging.warning("No Metasploit or Nuclei data loaded.")
        return pd.DataFrame()
    
    # Process each dataframe only if it's not empty
    dataframes = []
    if not metasploit_df.empty:
        metasploit_df.drop_duplicates(keep='first', inplace=True)
        metasploit_df['Source'] = 'Metasploit'
        dataframes.append(metasploit_df[['CVE', 'Source']])
    
    if not nuclei_df.empty:
        nuclei_df.drop_duplicates(keep='first', inplace=True)
        nuclei_df['Source'] = 'Nuclei'
        dataframes.append(nuclei_df[['CVE', 'Source']])
    
    return pd.concat(dataframes, ignore_index=True, sort=False) if dataframes else pd.DataFrame()

def load_cisa(cisa_path: Path) -> pd.DataFrame:
    """Load CISA Known Exploited Vulnerabilities data."""
    df = load_csv(cisa_path)
    if df.empty:
        return df
    df = df.rename(columns={"cveID": "CVE"})
    df['Source'] = 'CISA'
    return df[['CVE', 'Source']]

def load_epss(epss_path: Path) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load EPSS data and return filtered and full datasets."""
    df = load_csv(epss_path, skiprows=1)
    if df.empty:
        return df, df
    df = df.rename(columns={"cve": "CVE"})
    df_all = df.copy()
    df = df[df.epss > .95].copy()
    df['Source'] = 'EPSS'
    return df[['CVE', 'Source']], df_all

def load_nvd_data(filename: Path) -> List[Dict[str, Any]]:
    """Load NVD data from JSON file."""
    if not filename.exists():
        logging.error(f"Missing NVD file: {filename}")
        return []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from file {filename}: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error reading NVD file {filename}: {e}")
        return []

def extract_entry_data(entry: Dict[str, Any]) -> Dict[str, str]:
    """Extract relevant CVE data from NVD entry with improved error handling."""
    fields = {
        'assigner': 'Missing_Data',
        'published_date': 'Missing_Data',
        'attack_vector': 'Missing_Data',
        'attack_complexity': 'Missing_Data',
        'privileges_required': 'Missing_Data',
        'user_interaction': 'Missing_Data',
        'scope': 'Missing_Data',
        'confidentiality_impact': 'Missing_Data',
        'integrity_impact': 'Missing_Data',
        'availability_impact': 'Missing_Data',
        'base_score': '0.0',
        'base_severity': 'Missing_Data',
        'exploitability_score': 'Missing_Data',
        'impact_score': 'Missing_Data',
        'cwe': 'Missing_Data',
        'description': '',
        'cpe': '',
        'cvss_vector': ''
    }
    # Extract CPEs (if present)
    try:
        cpe_list = []
        configurations = entry.get('cve', {}).get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    cpe_uri = cpe.get('criteria') or cpe.get('cpe23Uri')
                    if cpe_uri:
                        cpe_list.append(cpe_uri)
        if cpe_list:
            fields['cpe'] = ';'.join(sorted(set(cpe_list)))
    except Exception as e:
        logging.warning(f"Error extracting CPEs: {e}")
    
    try:
        cve_data = entry.get('cve', {})
        if not isinstance(cve_data, dict):
            logging.warning(f"Invalid CVE data structure in entry")
            return fields
            
        fields['cve'] = cve_data.get('id', 'Unknown')
        fields['assigner'] = cve_data.get('sourceIdentifier', fields['assigner'])
        fields['published_date'] = cve_data.get('published', fields['published_date'])
        
        # Extract CVSS metrics with better error handling
        metrics_data = cve_data.get('metrics', {})
        cvss_metrics = metrics_data.get('cvssMetricV31', [])
        if cvss_metrics and isinstance(cvss_metrics, list):
            cvss_data = cvss_metrics[0].get('cvssData', {})
            fields.update({
                'attack_vector': cvss_data.get('attackVector', fields['attack_vector']),
                'attack_complexity': cvss_data.get('attackComplexity', fields['attack_complexity']),
                'privileges_required': cvss_data.get('privilegesRequired', fields['privileges_required']),
                'user_interaction': cvss_data.get('userInteraction', fields['user_interaction']),
                'scope': cvss_data.get('scope', fields['scope']),
                'confidentiality_impact': cvss_data.get('confidentialityImpact', fields['confidentiality_impact']),
                'integrity_impact': cvss_data.get('integrityImpact', fields['integrity_impact']),
                'availability_impact': cvss_data.get('availabilityImpact', fields['availability_impact']),
                'base_score': str(cvss_data.get('baseScore', fields['base_score'])),
                'base_severity': cvss_data.get('baseSeverity', fields['base_severity']),
                'exploitability_score': str(cvss_data.get('exploitabilityScore', fields['exploitability_score'])),
                'impact_score': str(cvss_data.get('impactScore', fields['impact_score'])),
                'cvss_vector': cvss_data.get('vectorString', cvss_data.get('attackVector', fields['cvss_vector']))
            })
        
        # Extract CWE information (collect all CWEs and strip CWE- prefix)
        weaknesses = cve_data.get('weaknesses', [])
        if weaknesses and isinstance(weaknesses, list):
            cwe_list = []
            for weakness in weaknesses:
                weakness_desc = weakness.get('description', [])
                if weakness_desc and isinstance(weakness_desc, list):
                    for desc in weakness_desc:
                        cwe_value = desc.get('value', '')
                        if cwe_value and cwe_value != 'Missing_Data':
                            # Strip CWE- prefix to keep only the number/identifier
                            if cwe_value.startswith('CWE-'):
                                cwe_value = cwe_value[4:]  # Remove 'CWE-' prefix
                            cwe_list.append(cwe_value)
            if cwe_list:
                fields['cwe'] = ', '.join(sorted(set(cwe_list)))
        
        # Extract description
        descriptions = cve_data.get('descriptions', [])
        if descriptions and isinstance(descriptions, list):
            fields['description'] = descriptions[0].get('value', fields['description'])
            
    except (KeyError, IndexError, TypeError) as e:
        logging.warning(f"Error extracting data from entry: {e}")
    
    return fields

def process_nvd_files(nvd_path: Path) -> pd.DataFrame:
    """Process NVD files and return a DataFrame with CVE data."""
    row_accumulator = []
    if not nvd_path.exists():
        logging.error(f"NVD file not found: {nvd_path}")
        return pd.DataFrame()
    
    nvd_data = load_nvd_data(nvd_path)
    if not nvd_data:
        logging.warning("No NVD data loaded from file")
        return pd.DataFrame()
    
    for entry in nvd_data:
        try:
            entry_data = extract_entry_data(entry)
            if not entry_data['description'].startswith('** REJECT **'):
                row_accumulator.append(entry_data)
        except Exception as e:
            logging.warning(f"Error processing NVD entry: {e}")
            continue
    
    if not row_accumulator:
        logging.warning("No valid NVD entries found")
        return pd.DataFrame()
    
    nvd = pd.DataFrame(row_accumulator)
    nvd = nvd.rename(columns={'published_date': 'Published'})
    nvd['Published'] = pd.to_datetime(nvd['Published'], errors='coerce')
    # Format as YYYY-MM-DD for output
    nvd['Published'] = nvd['Published'].dt.strftime('%Y-%m-%d')
    nvd = nvd.sort_values(by=['Published'])
    nvd = nvd.reset_index(drop=True)
    return nvd

def main() -> None:
    """Main function to orchestrate data processing."""
    parser = argparse.ArgumentParser(description="PatchThisApp Data Aggregator")
    parser.add_argument('--metasploit', type=Path, default=Path('metasploit.txt'))
    parser.add_argument('--nuclei', type=Path, default=Path('nuclei.txt'))
    parser.add_argument('--cisa', type=Path, default=Path('known_exploited_vulnerabilities.csv'))
    parser.add_argument('--epss', type=Path, default=Path('epss_scores-current.csv'))
    parser.add_argument('--nvd', type=Path, default=Path('nvd.jsonl'))
    parser.add_argument('--output', type=Path, default=Path('data/data.csv'))
    args = parser.parse_args()

    logging.info("Loading Metasploit and Nuclei data...")
    cve_sources = load_metasploit_nuclei(args.metasploit, args.nuclei)
    logging.info("Loading CISA data...")
    cisa_df = load_cisa(args.cisa)
    logging.info("Loading EPSS data...")
    epss_df, epss_df_all = load_epss(args.epss)
    
    if cve_sources.empty and cisa_df.empty and epss_df.empty:
        logging.error("No CVE source data loaded. Exiting.")
        return
    
    cve_list = pd.concat([cve_sources, epss_df, cisa_df], ignore_index=True, sort=False)
    cve_list = cve_list.groupby('CVE', as_index=False).agg({'CVE': 'first', 'Source': '/'.join})

    logging.info("Processing NVD data...")
    nvd = process_nvd_files(args.nvd)
    if nvd.empty:
        logging.error("No NVD data loaded. Exiting.")
        return
    nvd = nvd.rename(columns={'cve': 'CVE', 'description': 'Description', 'base_score': 'CVSS Score'})

    logging.info("Merging data and writing output...")
    patchthisapp_df = pd.merge(cve_list, nvd, how='inner', left_on='CVE', right_on='CVE')
    if not epss_df_all.empty:
        patchthisapp_df = pd.merge(patchthisapp_df, epss_df_all, how='inner', left_on='CVE', right_on='CVE')
        columns = ['CVE', 'CVSS Score', 'cvss_vector', 'epss', 'Description', 'Published', 'Source', 'cwe', 'cpe']
        patchthisapp_df = patchthisapp_df[columns]
        patchthisapp_df = patchthisapp_df.rename(columns={"epss": "EPSS", "cvss_vector": "CVSS_Vector", "cwe": "CWE", "cpe": "CPE"})
    else:
        columns = ['CVE', 'CVSS Score', 'cvss_vector', 'Description', 'Published', 'Source', 'cwe', 'cpe']
        patchthisapp_df = patchthisapp_df[columns]
        patchthisapp_df = patchthisapp_df.rename(columns={"cvss_vector": "CVSS_Vector", "cwe": "CWE", "cpe": "CPE"})
    
    args.output.parent.mkdir(parents=True, exist_ok=True)
    patchthisapp_df.to_csv(args.output, index=False, encoding='utf-8', lineterminator='\n')
    logging.info(f"Wrote output to {args.output}")
    
    # Also save a copy to the web folder for the CSV viewer
    web_csv_path = Path('web/data.csv')
    web_csv_path.parent.mkdir(parents=True, exist_ok=True)
    patchthisapp_df.to_csv(web_csv_path, index=False, encoding='utf-8', lineterminator='\n')
    logging.info(f"Wrote web copy to {web_csv_path}")
    
    # Also save a copy to the web/viewer folder for the CSV viewer
    web_viewer_csv_path = Path('web/viewer/data.csv')
    web_viewer_csv_path.parent.mkdir(parents=True, exist_ok=True)
    patchthisapp_df.to_csv(web_viewer_csv_path, index=False, encoding='utf-8', lineterminator='\n')
    logging.info(f"Wrote web viewer copy to {web_viewer_csv_path}")

if __name__ == "__main__":
    main()
