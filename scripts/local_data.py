import os
import subprocess
import shutil
import platform
import time


def run_command(cmd):
    """Run a shell command and exit on failure."""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"Command failed: {cmd}")
        exit(result.returncode)


def ensure_tool(tool, install_cmds):
    """Ensure a tool is installed, try install_cmds if not found."""
    if shutil.which(tool) is None:
        print(f"{tool} not found. Attempting to install...")
        for cmd in install_cmds:
            try:
                run_command(cmd)
                if shutil.which(tool):
                    print(f"{tool} installed successfully.")
                    return
            except Exception:
                pass
        print(f"Failed to install {tool}. Please install it manually.")
        exit(1)


def main():
    """Download all required data files for local testing."""
    system = platform.system()
    # Install dependencies (jq, wget, curl, gzip)
    if system == "Darwin":  # macOS
        if shutil.which("brew") is None:
            print("Homebrew not found. Please install Homebrew from https://brew.sh/ and re-run this script.")
            exit(1)
        ensure_tool("jq", ["brew install jq"])
        ensure_tool("wget", ["brew install wget"])
        ensure_tool("curl", ["brew install curl"])
        ensure_tool("gzip", ["brew install gzip"])
    elif system == "Linux":
        ensure_tool("jq", ["sudo apt-get update && sudo apt-get install jq -y"])
        ensure_tool("wget", ["sudo apt-get update && sudo apt-get install wget -y"])
        ensure_tool("curl", ["sudo apt-get update && sudo apt-get install curl -y"])
        ensure_tool("gzip", ["sudo apt-get update && sudo apt-get install gzip -y"])
    else:
        print(f"Unsupported OS: {system}")
        exit(1)

    # Download EPSS data with retry
    for i in range(1, 4):
        if os.system('wget https://epss.empiricalsecurity.com/epss_scores-current.csv.gz -O epss_scores-current.csv.gz') == 0:
            break
        elif i == 3:
            print('Failed to download EPSS data after 3 attempts')
            exit(1)
        else:
            print(f'Attempt {i} failed, retrying...')
            time.sleep(5)
    run_command('gzip -f -d epss_scores-current.csv.gz')

    # Download Metasploit data
    run_command(
        "curl -sSf https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json | "
        "jq -r '.[]|{cve:.references[]|select(startswith(\"CVE-\"))}| join(\",\")' > metasploit.txt || touch metasploit.txt"
    )

    # Download Nuclei data
    run_command(
        "curl -sSf https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json | "
        "jq -r .ID > nuclei.txt || touch nuclei.txt"
    )

    # Download CISA KEV data
    run_command(
        'wget https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv '
        '-O known_exploited_vulnerabilities.csv'
    )

    # Download NVD data
    run_command(
        'wget https://nvd.handsonhacking.org/nvd.jsonl -O nvd.jsonl || touch nvd.jsonl'
    )


if __name__ == "__main__":
    main()
