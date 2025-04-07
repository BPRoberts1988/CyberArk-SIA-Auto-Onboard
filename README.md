# CyberArk-SIA-Auto-Onboard
WARNING: The provided script is not meant to be used in production. This script requires hard-coded credentials, which is inherently not secure. Please only use this script for testing and ensure that it is updated/modified to use secure strings or that the credential is retrieved from a Vault such as the CyberArk Vault. https://docs.cyberark.com/credential-providers/latest/en/content/ccp/the-cyberark-application-identity-management-solution.htm?tocpath=Get%20Started%7C_____1

This script was tested against Windows Server 2019 and Windows Server 2022 utilizing Privilege Cloud API's. PAM Self-Hosted API's may require modification before implementing.

This repository provides a PowerShell script that can be used to automatically on-board non-domain joined systems. The following lines will need to be updated before using the script:

Lines 2 - 7: will need to be updated with credentials, safe name, and domain name (optional). 
Line 21: Update path of generated log file.
Line 49: Update the Identity URI to match your tenant (Example: https://abc1234.id.cyberark.cloud). 
Line 74, Line 110: Update the PAM/Privilege Cloud URI (Example: https://<<sub-domain>>.privilegecloud.cyberark.cloud).
Line 215, Line 243: Update the SIA URI (Example: https://<<sub-domain>>.dpa.cyberark.cloud/api).

With CyberArk Secure Infrastructure Access, a domain account would typically be used as a strong account to cover an entire environment. However, this use case assumes that there are non-domain joined systems that need to be on-boarded. 

This script makes several assumptions:

1. Local Administrator account is being on-boarded and configured as a Strong Account to allow for ephemeral access to the target server. https://docs.cyberark.com/ispss-access/latest/en/content/hometileslps/dpa-lp-tile8.htm
2. This script will be distributed via a script distribution tool such as JAMF, InTune, or CyberArk EPM. https://docs.cyberark.com/epm/latest/en/content/policies/scriptdistributionpolicies-newui.htm
3. A domain can be manually defined in this script to allow for FQDN based management. If DNS automatically creates new Hostname (A or AAAA), the domain does not need to be manually declared and can be removed from the script.

The script performs the following actions

1. Authenticates to CyberArk Shared Services via Identity OAUTH Service User
2. Identifies the local Administrator account associated with SID 500
3. The script generates a completely random password and resets the SID 500 Admin User password.
4. The script then checks for a defined safe to store the account in. If the account is already on-boarded, this step is skipped. This check is performed by ensuring that $hostName-$adminName is not already stored in the vault.
5. Once the account is on-boarded, the script will configure the account as a strong account.
6. Once the account is configured as a strong account, a target set is configured based on the hostname/domain data gathered previously.

Comments and suggestions are welcome.
