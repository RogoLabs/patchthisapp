# patchthisapp.py
# Modernized: pathlib, type hints, argparse, modularization, logging, __main__ guard, file checks

from pathlib import Path
import argparse
import json
import logging
import pandas as pd
from typing import List, Dict, Tuple, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DEFAULT_VENDOR_BRAND_MAP = {
    'Dlink': 'D-Link',
    'Tp-Link': 'TP-Link',
    'Linksys': 'Linksys',
}


def load_vendor_brand_map(path: Path) -> Dict[str, str]:
    """Load vendor brand casing map from JSON; fallback to built-in defaults."""
    if not path.exists():
        return dict(DEFAULT_VENDOR_BRAND_MAP)

    try:
        with open(path, 'r', encoding='utf-8') as f:
            loaded = json.load(f)
        if not isinstance(loaded, dict):
            logging.warning(f"Vendor brand map at {path} is not a JSON object. Using defaults.")
            return dict(DEFAULT_VENDOR_BRAND_MAP)

        # Only accept string keys/values to avoid malformed map entries.
        normalized = {
            str(k): str(v)
            for k, v in loaded.items()
            if isinstance(k, str) and isinstance(v, str)
        }
        merged = dict(DEFAULT_VENDOR_BRAND_MAP)
        merged.update(normalized)
        return merged
    except Exception as e:
        logging.warning(f"Failed to load vendor brand map from {path}: {e}. Using defaults.")
        return dict(DEFAULT_VENDOR_BRAND_MAP)


VENDOR_BRAND_MAP = load_vendor_brand_map(Path(__file__).with_name('vendor_brand_map.json'))

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

    # Keep vendor/product context from KEV for fallback when NVD CPE parsing
    # does not produce Vendor/Affected Products.
    if 'vendorProject' not in df.columns:
        df['vendorProject'] = ''
    if 'product' not in df.columns:
        df['product'] = ''

    df = df.rename(columns={"vendorProject": "cisa_vendor", "product": "cisa_product"})
    return df[['CVE', 'Source', 'cisa_vendor', 'cisa_product']]

def load_epss(epss_path: Path, threshold: float = 0.95) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load EPSS data and return filtered and full datasets."""
    df = load_csv(epss_path, skiprows=1)
    if df.empty:
        return df, df
    df = df.rename(columns={"cve": "CVE"})
    df_all = df.copy()
    df = df[df.epss > threshold].copy()
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

def normalize_cpe_token(token: str) -> str:
    """Normalize one CPE token into a readable label."""
    if not token or token in {'*', '-'}:
        return ''
    cleaned = token.replace('\\', '').replace('_', ' ').strip()
    if not cleaned:
        return ''
    # Collapse repeated whitespace and normalize casing for readability.
    cleaned = ' '.join(cleaned.split())
    return cleaned.title()


def normalize_vendor_brand(vendor: str, brand_map: Dict[str, str] = None) -> str:
    """Normalize known vendor brand casing for display consistency."""
    if not vendor:
        return ''

    effective_map = brand_map if brand_map is not None else VENDOR_BRAND_MAP
    return effective_map.get(vendor, vendor)


def parse_cpe_fields(cpe_string: str) -> Tuple[str, str]:
    """Extract normalized vendor and product from a CPE 2.3 string."""
    if not cpe_string or not cpe_string.startswith('cpe:2.3:'):
        return ('', '')

    parts = cpe_string.split(':')
    if len(parts) < 5:
        return ('', '')

    vendor = normalize_vendor_brand(normalize_cpe_token(parts[3]))
    product = normalize_cpe_token(parts[4])
    return (vendor, product)


def choose_primary_vendor_product(cpe_list: List[str]) -> Tuple[str, str]:
    """Choose the best vendor/product candidate from a list of CPE values."""
    best_vendor = ''
    best_product = ''
    best_score = -1

    for cpe_string in cpe_list:
        vendor, product = parse_cpe_fields(cpe_string)
        if not vendor and not product:
            continue

        parts = cpe_string.split(':')
        cpe_part = parts[2] if len(parts) > 2 else ''

        score = 0
        if vendor:
            score += 2
        if product:
            score += 2
        if cpe_part == 'o':
            score += 3
        elif cpe_part == 'h':
            score += 2
        elif cpe_part == 'a':
            score += 1
        if 'firmware' in product.lower():
            score += 1

        if score > best_score:
            best_score = score
            best_vendor = vendor
            best_product = product

    return (best_vendor, best_product)


def first_non_empty(series: pd.Series) -> str:
    """Return the first non-empty, non-null value from a Series."""
    for value in series:
        if pd.notna(value):
            text = str(value).strip()
            if text:
                return text
    return ''

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
        'cvss_vector': '',
        'vendor': '',
        'product': ''
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
            vendor, product = choose_primary_vendor_product(cpe_list)
            fields['vendor'] = vendor
            fields['product'] = product
    except Exception as e:
        logging.warning(f"Error extracting CPEs: {e}")
    
    try:
        cve_data = entry.get('cve', {})
        if not isinstance(cve_data, dict):
            logging.warning("Invalid CVE data structure in entry")
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
        
        # Extract CWE information
        weaknesses = cve_data.get('weaknesses', [])
        if weaknesses and isinstance(weaknesses, list):
            weakness_desc = weaknesses[0].get('description', [])
            if weakness_desc and isinstance(weakness_desc, list):
                fields['cwe'] = weakness_desc[0].get('value', fields['cwe'])
        
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
    parser.add_argument('--epss-threshold', type=float, default=0.95,
                        help='EPSS score threshold (default: 0.95)')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose/debug logging')
    parser.add_argument('--dry-run', action='store_true',
                        help='Report what would be produced without writing files')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info("Loading Metasploit and Nuclei data...")
    cve_sources = load_metasploit_nuclei(args.metasploit, args.nuclei)
    logging.info("Loading CISA data...")
    cisa_df = load_cisa(args.cisa)
    logging.info("Loading EPSS data...")
    epss_df, epss_df_all = load_epss(args.epss, args.epss_threshold)
    
    if cve_sources.empty and cisa_df.empty and epss_df.empty:
        logging.error("No CVE source data loaded. Exiting.")
        return
    
    cve_list = pd.concat([cve_sources, epss_df, cisa_df], ignore_index=True, sort=False)
    if 'cisa_vendor' not in cve_list.columns:
        cve_list['cisa_vendor'] = ''
    if 'cisa_product' not in cve_list.columns:
        cve_list['cisa_product'] = ''

    cve_list = cve_list.groupby('CVE', as_index=False).agg({
        'CVE': 'first',
        'Source': lambda s: '/'.join(sorted(set(filter(None, (str(v).strip() for v in s))))),
        'cisa_vendor': first_non_empty,
        'cisa_product': first_non_empty,
    })

    logging.info("Processing NVD data...")
    nvd = process_nvd_files(args.nvd)
    if nvd.empty:
        logging.error("No NVD data loaded. Exiting.")
        return
    nvd = nvd.rename(columns={'cve': 'CVE', 'description': 'Description', 'base_score': 'CVSS Score'})

    logging.info("Merging data and writing output...")
    patchthisapp_df = pd.merge(cve_list, nvd, how='inner', left_on='CVE', right_on='CVE')

    # Fill empty vendor/product from CISA when NVD CPE parsing yields blanks.
    patchthisapp_df['vendor'] = patchthisapp_df['vendor'].fillna('')
    patchthisapp_df['product'] = patchthisapp_df['product'].fillna('')
    patchthisapp_df['cisa_vendor'] = patchthisapp_df['cisa_vendor'].fillna('')
    patchthisapp_df['cisa_product'] = patchthisapp_df['cisa_product'].fillna('')
    patchthisapp_df.loc[patchthisapp_df['vendor'].str.strip() == '', 'vendor'] = patchthisapp_df['cisa_vendor']
    patchthisapp_df.loc[patchthisapp_df['product'].str.strip() == '', 'product'] = patchthisapp_df['cisa_product']

    if not epss_df_all.empty:
        patchthisapp_df = pd.merge(patchthisapp_df, epss_df_all, how='inner', left_on='CVE', right_on='CVE')
        columns = ['CVE', 'CVSS Score', 'cvss_vector', 'epss', 'cwe', 'Description', 'Published', 'Source', 'cpe', 'vendor', 'product']
        patchthisapp_df = patchthisapp_df[columns]
        patchthisapp_df = patchthisapp_df.rename(columns={
            "epss": "EPSS", "cvss_vector": "CVSS_Vector", "cwe": "CWE", "cpe": "CPE",
            "vendor": "Vendor", "product": "Affected Products"
        })
    else:
        columns = ['CVE', 'CVSS Score', 'cvss_vector', 'cwe', 'Description', 'Published', 'Source', 'cpe', 'vendor', 'product']
        patchthisapp_df = patchthisapp_df[columns]
        patchthisapp_df = patchthisapp_df.rename(columns={
            "cvss_vector": "CVSS_Vector", "cwe": "CWE", "cpe": "CPE",
            "vendor": "Vendor", "product": "Affected Products"
        })
    
    logging.info(f"Final dataset: {len(patchthisapp_df)} CVEs")
    if args.dry_run:
        logging.info("Dry run mode — no files written")
        logging.info(f"Columns: {list(patchthisapp_df.columns)}")
        logging.info(f"Sample:\n{patchthisapp_df.head()}")
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    patchthisapp_df.to_csv(args.output, index=False)
    logging.info(f"Wrote output to {args.output}")
    
    # Also save a copy to the web folder for the CSV viewer
    web_csv_path = Path('web/data.csv')
    web_csv_path.parent.mkdir(parents=True, exist_ok=True)
    patchthisapp_df.to_csv(web_csv_path, index=False)
    logging.info(f"Wrote web copy to {web_csv_path}")
    

if __name__ == "__main__":
    main()
