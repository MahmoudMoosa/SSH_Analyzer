An SSH Brute-Force Detector built with Python! 

🔍 What it does: 
- Monitors `/var/log/auth.log` for failed SSH attempts. 
- Flags IPs with excessive failures (configurable threshold). 
- Sends real-time alerts to Splunk for SOC teams. 

🛠 Tech Stack: 
- Python (Pandas, Regex, Requests) 
- Splunk HEC 

💡 Why this matters: 
Automating threat detection frees up SOC analysts to focus on critical incidents. 
