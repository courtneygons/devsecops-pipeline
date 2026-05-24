# IAM Access Key Auditor
# This script checks for AWS access keys that are older than 90 days
# Old keys are a security risk and should be rotated regularly

import boto3
from datetime import datetime, timezone

def check_old_keys(max_days=90):
    """
    Connects to AWS and lists any access keys older than max_days.
    Prints a warning for each one found.
    """
    iam = boto3.client('iam')
    
    # Get all IAM users in the account
    users = iam.list_users()
    
    print(f"Checking all IAM users for keys older than {max_days} days...\n")
    
    for user in users['Users']:
        username = user['UserName']
        
        # Get the access keys for this user
        keys = iam.list_access_keys(UserName=username)
        
        for key in keys['AccessKeyMetadata']:
            # Calculate how old the key is
            created = key['CreateDate']
            age = datetime.now(timezone.utc) - created
            days_old = age.days
            
            if days_old > max_days:
                print(f"⚠️  WARNING: {username} has a key that is {days_old} days old")
                print(f"   Key ID: {key['AccessKeyId']}")
                print(f"   Action needed: rotate or delete this key\n")
            else:
                print(f"✅ {username} — key is {days_old} days old. OK.")

if __name__ == "__main__":
    check_old_keys()
