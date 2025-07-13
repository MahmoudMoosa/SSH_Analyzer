#!/usr/bin/env python3

import re
from collections import defaultdict
import pandas
import requests
import json
import time

LOGFILE = "/var/log/auth.log"  # default log path in Linux
SPLUNK_URL = "https://prd-p-rja6i.splunkcloud.com:8088/services/collector"
SPLUNK_TOKEN = "58554db2-4b99-4b06-a857-9536248a5433"
# function to make a dictionary of IPs and there failed attempts
def authin_logs(log_file):
    fail_attemp = defaultdict(int)
    ip_pattern = re.compile(r'Failed password for .* from (\S+) port \d+') 
    
    try:
        with open(log_file, 'r') as file:
            for line in file:
                match = ip_pattern.search(line)
                if match:  #extracting IP and incrementing the counter
                    ip = match.group(1) 
                    fail_attemp[ip] += 1
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_file}")
        exit(1)
    
    fail_attemp == 0
    return fail_attemp

# Change dictionary to DataFrame for easy analysis 
def generatin_report(fail_attemp, threshold=5):
    data_frame = pandas.DataFrame(list(fail_attemp.items()), columns=['IP', 'Failed Attempts'])
    
    sus_ip = data_frame[data_frame['Failed Attempts'] >= threshold]
    
    if not sus_ip.empty:
        print("A Brute Force attack is detected from the following IPs:")
        print(sus_ip.to_string(index=False))
        return sus_ip
    else:
        print("There is no Brute force attack detected.")
        return None
        

def splunk_integ(ip, attempts):

    payload = {
        "event": {  
            "message": f"SSH attack from {ip}",
            "ip": ip,
            "attempts": attempts,
            "severity": "high"
        },
        "sourcetype": "ssh_bruteforce",  
        "source": "python_script"        
    }
    headers = {"Authorization": "Splunk 58554db2-4b99-4b06-a857-9536248a5433"}

    response = requests.post(
        "https://prd-p-rja6i.splunkcloud.com:8088/services/collector",
        json=payload,
        headers=headers,
        verify=False
    )
    print("Splunk Response:", response.text)
                

    try:
        response = requests.post(SPLUNK_URL, json=payload, headers=headers, verify=False)  # Disable SSL verify for testing (enable in prod)
        response.raise_for_status()
        print(f"Alert sent to Splunk: {ip}")
    except Exception:
            print(f"[ERROR] Splunk HEC failed: {type(Exception)} - {str(Exception)}")
            
            
            
            
# Now The main excution
if __name__ == "__main__":
    fail_attemp = authin_logs(LOGFILE)
    
    report = generatin_report(fail_attemp)
    
    if report is not None:
        report.to_csv("suspicious_IPs.csv", index=False)
        print("Report Saved to the file")
    
    if report is not None:
        for _, row in report.iterrows():
            splunk_integ(row['IP'], row['Failed Attempts'])
