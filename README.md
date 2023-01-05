# Wuyts Lander's SOC
I have created a small SOC in my AWS environment.
This repo contains instructions and relevant files to recreate my setup.

## Table of Contents
*fill in later**

## Overview

The SOC contains the following elements:
- A Ubuntu server that serves as the production environment
- A Ubuntu server hosting Wazuh, which collects & detects events, as well as serving as a SIEM
- A Ubuntu server hosting Shuffle.io, which automates the actions taken on certain events, thus serving as a SOAR
- A Ubuntu server hosting TheHive and Cortex, serving as an incident response manager

All of these are hosted in AWS EC2 instances.
They have their own internal subnet, and are accessible with public IP addresses. 

In the current setup, the workflow is triggered when a SSH login attempt is rejected,
prompting new events in TheHive and a new message in the SOC's Discord server.

## AWS Infrastructure

This SOC was created using an AWS Learner Lab licence. 
All software runs on EC2 instances.   
No scalability or elasticity was implemented, as the scale of this project does not require it.  
In this section, the details of the AWS infrastructure are described.

### VPC

Before setting up the EC2 instances, a VPC named "SOC-vpc" is created to separate these instances internally from the larger subnet
and give more control over the internal IP addresses.

The IP subnet chosen was 10.0.2.0/24. 
There is no specific reason for this, other than VirtualBox also using this on my (previously created) local setup.  
When creating EC2 instances, the (automatically generated) 10.0.2.0/28 subnet is used.

<img src="assets/AWS/VPC/SOC.png" alt="SOC-vpc" width="75%"/>

### Security Group

To centralize inbound/outbound port rules, a single Security Group was created for all four EC2 instances.  
In a larger production environment, every instance or group of instances would likely get assigned to a separate security group.  
However, for the scale of this project one group will suffice.

The configuration of this security group and its rules can be found in [AWS\SecurityGroup](AWS/SecurityGroup/).  
The CSV files found here can be imported into AWS.

The inbound rules for Wazuh were based on the [Wazuh documentation](https://documentation.wazuh.com/current/getting-started/architecture.html#required-ports).

<img src="assets/AWS/Security Group inbound rules.png" alt="inbound rules" width="75%"/>

### EC2 instances

| Name | OS | AMI | Instance type | Key pair | VPC | Subnet | Auto-assign public IP | Security group | Storage |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Wazuh | Ubuntu Server 22.04 LTS | ami-0574da719dca65348 (64-bit (x86)) | t2.large | pckey.pem | [SOC-vpc](#vpc) | 10.0.2.0/28 | Enable | [SOC](#security-group) | 50 GB |
| Agent | Ubuntu Server 22.04 LTS | ami-0574da719dca65348 (64-bit (x86)) | t2.micro | pckey.pem | [SOC-vpc](#vpc) | 10.0.2.0/28 | Enable | [SOC](#security-group) | 8 GB |
| Shuffle.io | Ubuntu Server 22.04 LTS | ami-0574da719dca65348 (64-bit (x86)) | t2.medium | pckey.pem | [SOC-vpc](#vpc) | 10.0.2.0/28 | Enable | [SOC](#security-group) | 100 B |
| TheHive | Ubuntu Server 22.04 LTS | ami-0574da719dca65348 (64-bit (x86)) | t2.medium | pckey.pem | [SOC-vpc](#vpc) | 10.0.2.0/28 | Enable | [SOC](#security-group) | 50 GB |

The key pair "pckey.pem" was created to access these instances over SSH.  
To set the right permissions on the key, the following commands were executed:[^1]
```PowerShell
$path = "~\.ssh\pckey.pem"
# Reset to remove explict permissions
icacls.exe $path /reset
# Give current user explicit read-permission
icacls.exe $path /GRANT:R "$($env:USERNAME):(R)"
# Disable inheritance and remove inherited permissions
icacls.exe $path /inheritance:r
```

Public IP addresses are assigned dynamically on startup and thus change regularly.  
After the instances are created, the following (local) IP addresses were assigned:

| Name | local IPv4 address |
| -- | -- |
| Wazuh | 10.0.2.9 |
| Agent | 10.0.2.6 |
| Shuffle.io | 10.0.2.11 |
| TheHive | 10.0.2.14 |

## Setup

The concept of this SOC was inspired by [Taylor Walton's video on combinging Shuffle, Wazuh, TheHive and Cortex](https://www.youtube.com/watch?v=FBISHA7V15c)[^9],
as well as many of his other instructional video's and the official documentation of the various technologies used (see the [sources](#sources)).

All instances had their timezone (manually) set with the following command:
```shell
sudo timedatectl set-timezone Europe/Brussels
```

### Wazuh
The Wazuh instance was created following the [installation assistant](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/installation-assistant.html).[^12]

### Wazuh agent

### Shuffle.io

### TheHive and Cortex

## Learner Lab / VM restart

When the VM's are stopped and restarted, the public IP address changes.  
This happens when the learner lab restarts.  
In this case, the following actions need to be taken:  

The **Shuffle.io webhook** URL needs to be replaced in the Wazuh configuration:
- Go to the *Shuffle webapp*, select the webhook and copy the URL
- Go to the *Wazuh instance* and replace the URL in the integration section of /var/ossec/etc/ossec.conf
- Restart the Wazuh manager
```sh
sudo nano /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

The following **services** must be started on the *TheHive instance*:
- thehive
- elasticsearch
- cortex
```sh
sudo service thehive start
sudo service cortex start
sudo service elasticsearch start
```

## Workflow

### Attack

```PowerShell
ssh -i "<path to fake SSH key>" ubuntu@ec2-<agent IP with - instead of .>.compute-1.amazonaws.com
```

## Project status

## Sources
[^1]: Randhawa, J. (2018-06-29). *Set permission of file equivalent to chmod 400 on Windows*. Retrieved from gist.github.com: https://gist.github.com/jaskiratr/cfacb332bfdff2f63f535db7efb6df93

[^2]: Shuffle AS. (n.d.). *Configure Shuffle*. Retrieved from shuffler.io: https://shuffler.io/docs/configuration

[^3]: TheHive Project. (2021-06-02). *Step-by-Step guide*. Retrieved from docs.thehive-project.org: https://docs.thehive-project.org/thehive/installation-and-configuration/installation/step-by-step-guide/

[^4]: TheHive Project. (2022-07-07). *Installation Guide*. Retrieved from github.com: https://github.com/TheHive-Project/CortexDocs/blob/master/installation/install-guide.md#deb

[^5]: Walton, T. (2021-06-25). *TheHive - Build Your Own Security Operations Center (SOC)*. Retrieved from youtube.com: https://www.youtube.com/watch?v=VqIuP0AOCBg

[^6]: Walton, T. (2021-07-27). *CORTEX - Analyze Observables (IPs, domains, etc.) at Scale! - Build Your Own Intelligence Platform!*. Retrieved from youtube.com: https://www.youtube.com/watch?v=qz6xtINwK3I

[^7]: Walton, T. (2021-07-29). *TheHive and Cortex Integration - Add Intelligence to Your SOC!*. Retrieved from youtube.com: https://www.youtube.com/watch?v=lzsTSDJhAOw

[^8]: Walton, T. (2021-11-28). *Host Your Own SOAR - Shuffle Install*. Retrieved from youtube.com: https://www.youtube.com/watch?v=YDUKZojg0vk

[^9]: Walton, T. (2021-12-13). *Shuffle + Wazuh + TheHIVE + Cortex = Automation Bliss*. Retrieved from youtube.com: https://www.youtube.com/watch?v=FBISHA7V15c

[^10]: Wazuh Inc. (n.d.). *All-in-one deployment*. Retrieved from documentation.wazuh.com: https://documentation.wazuh.com/current/deployment-options/elastic-stack/all-in-one-deployment/index.html#adding-the-elastic-stack-repository

[^11]: Wazuh Inc. (n.d.). *Architecture*. Retrieved from documentation.wazuh.com: https://documentation.wazuh.com/current/getting-started/architecture.html#required-ports

[^12]: Wazuh Inc. (n.d.). *Wazuh indexer*. Retrieved from documentation.wazuh.com: https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html
