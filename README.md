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

The inbound rules for Wazuh were based on the [Wazuh documentation](https://documentation.wazuh.com/current/getting-started/architecture.html#required-ports)[^11].

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

#### Indexer

Download the Wazuh installation assistant and the configuration file:

```sh
curl -sO https://packages.wazuh.com/4.3/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.3/config.yml
```

The configuration file 'config.yml' was edited to resemble the file in the [Wazuh directory](/Wazuh/~/config.yml).

Then, the Wazuh cluster key, certificates and passwords are generated with the following command:

```sh
bash wazuh-install.sh --generate-config-files
```

Next, the indexer nodes are installed.
```sh
curl -sO https://packages.wazuh.com/4.3/wazuh-install.sh
bash wazuh-install.sh --wazuh-indexer node-1
```

After this, the cluster is initialized.
```sh
bash wazuh-install.sh --start-cluster
```

To get the password belonging to the **admin**-user, use the following command:
```sh
tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1
```

To confirm the installation, use the following command, replacing <ADMIN_PASSWORD> with the password received in the command above.
Replace <WAZUH_INDEXER_IP> with the IP set in the config file, 10.0.2.9 in this case.
```sh
# Check the installation
curl -k -u admin:<ADMIN_PASSWORD> https://<WAZUH_INDEXER_IP>:9200
# Check if the cluster is working correctly
curl -k -u admin:<ADMIN_PASSWORD> https://<WAZUH_INDEXER_IP>:9200/_cat/nodes?v
```

The output should look like this:
```json
{
  "name" : "node-1",
  "cluster_name" : "wazuh-cluster",
  "cluster_uuid" : "cMeWTEWxQWeIPDaf1Wx4jw",
  "version" : {
    "number" : "7.10.2",
    "build_type" : "rpm",
    "build_hash" : "e505b10357c03ae8d26d675172402f2f2144ef0f",
    "build_date" : "2022-01-14T03:38:06.881862Z",
    "build_snapshot" : false,
    "lucene_version" : "8.10.1",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
```

#### Server

In the same directory as before, run:
```sh
bash wazuh-install.sh --wazuh-server wazuh-1
```

That's it! Easy, innit?

#### Dashboard

The dashboard is not really required for this SOC, but it gives a nice overview when troubleshooting.
It is installed with the following code:
```sh
bash wazuh-install.sh --wazuh-dashboard dashboard
```

You can now access the Wazuh dashboard at *https://<Wazuh instance public IP>* using the username "admin" and the password requested earlier.

### Wazuh agent

The Wazuh agent is a simple, lightweight Ubuntu server with the default Wazuh agent configuration applied.  
These instructions can be found using the [Wazuh Dashboard](#dashboard), and go as follows:
```sh
curl -so wazuh-agent-4.3.10.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb && sudo WAZUH_MANAGER='10.0.2.9' WAZUH_AGENT_GROUP='SOC' dpkg -i ./wazuh-agent-4.3.10.deb
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Assuming the IP is set to 10.0.2.9 and you created a group named SOC.  
The group is not necessary for this SOC, but could be used for other configurations.  
You can just add the agent to the default group if you wish.

### Shuffle.io

Shuffle.io was installed using the [official Shuffle documentation](https://shuffler.io/docs/configuration)[^2]
and a [video tutorial](https://youtu.be/YDUKZojg0vk)[^8].

First, install Docker and Docker-compose:
```sh
sudo snap install docker
```

Next, install Shuffle:
```sh
git clone https://github.com/frikky/Shuffle
cd Shuffle
docker-compose up -d
```

Ensure that the shuffle-database folder has the right owner/group:
```sh
sudo chown 1000:1000 -R shuffle-database
```

You can now log in to the Shuffle.io dashboard via *https://<Shuffle instance public IP>:3443*, using the username "admin" and password "admin".  
The creation of the actual workflow is explained in more detail in [Workflow](#workflow).

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
