import os
import subprocess

# WEAK POINT 5: Hardcoded AWS Access Key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def backup_s3_bucket(bucket_name):
    # WEAK POINT 6: Command injection via shell execution
    command = f"aws s3 sync s3://{bucket_name} /data/backups"
    os.system(command)

def execute_diagnostics(ip_address):
    subprocess.Popen(f"traceroute {ip_address}", shell=True)
