# Homework Assignment: Docker Container Setup with Wazuh for Vulnerability Scanning and Log Aggregation

## Assignment
### Objective
The goal of this homework assignment is to assess your ability to set up and configure Docker containers, install and configure security tools, and perform vulnerability scanning and log aggregation.
Specifically, you will set up Docker containers: running Wazuh and running a vulnerable application. You will then install the Wazuh agent on the vulnerable application container, perform a vulnerability scan, and configure log aggregation to the Wazuh manager

### Instructions
Create a GitHub repository and push the following items:
* Docker compose
* The copied Wazuh configuration file (wazuh-manager-ossec.conf)
* Any additional scripts or configuration files used
* A README.md file with detailed steps followed, screenshots where applicable, and explanations of configurations

### Links
* Wazuh docker compose
https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
* Vulnerable container
https://hub.docker.com/r/vulnerables/web-dvwa


## Implementation
### Initial installation of Wazuh 
First, Linux was configured using the next configuration:
* Docker compose installation and system configuration: https://documentation.wazuh.com/current/deployment-options/docker/docker-installation.html
```
sysctl -w vm.max_map_count=262144
curl -sSL https://get.docker.com/ | sh
systemctl start docker
curl -L "https://github.com/docker/compose/releases/download/v2.12.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
docker-compose --version # Docker Compose version v2.12.2
```

* Afterwards, all steps were followed as mentioned in documentation provided: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
```
git clone https://github.com/wazuh/wazuh-docker.git -b v4.8.1
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator
docker-compose up -d
```

**NB! Please bear in mind that this is a set up for DEV environment. Therefore, there were no specific configurations made, for example all passwords are left default. Docker compose file could be found under: /wazuh-docker/docker-compose.yml**

Screenshot after initial Wazuh installation:
![Alt text](/screenshots/after_initial_wazuh_install_1.jpg?raw=true "After initial Wazuh install")

### Initial Wazuh configuration and Agent installation
After docker containers are up and running, I have verified that Wazuh is working fine, by logging in with default credentials. 
At first, I have decided to create a sample group, which will be used by agents.
`` To do so, I went to Server management -> Endpoint Groups -> Add new. ``
This step could be also done in different ways (for example via executing the next command on the server manager itself: /var/ossec/bin/agent_groups -a -g group_name -q).

For the first agent install, you should see "Add agent" on the main page of Wazuh. For futurue agent deployments, you could also go to `` Server management -> Endpoints Summary -> Deploy new agent ``
The next command was used to deploy the Wazuh agent:
```
sudo wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.1-1_amd64.deb && sudo WAZUH_MANAGER='192.168.75.133' WAZUH_AGENT_GROUP='container,default' WAZUH_AGENT_NAME='ubuntu_client_1' dpkg -i ./wazuh-agent_4.8.1-1_amd64.deb
```

Afterwards, reload daemon and start wazuh-agent:
```
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Screenshot after first wazuh agent installation (later I have changed to a more self-explanatory Agent name):
![Alt text](/screenshots/after_initial_wazuh_install_2.jpg?raw=true "After initial Wazuh Agent install")

In case I understood the task right, it is required to monitor docker container via installing agent specifically on the container. 
However, after investigation, it seems that usually, it is recommended to monitor docker containers from the server, which hosts containers. 

From my point of view, monitoring of server itself could be better in terms of security, scalability and ease of deployment. 
* Security: it is for sure better to monitor server itself, because if there are any steps done on the server level, it could have more impact on the whole infrastructure.
* Scalability: it is possible to monitor all docker containers running on the server from the server agents. This means that it is not required to create a custom docker compose file for each docker deployment. It also mitigates the use-case, when someone decided to deploy the container without agent.
* Additionally, it could be also easier depending on containers deployed. For example, DVWA container has a broken initial setup, where ``apt-get update && apt-get install wget`` will fail by default. This could be fixed for a specific package, but I have some doupts on scalability of such system.
Additionally, as stated in https://docs.docker.com/config/containers/multi-service_container/: "It is generally recommended that you separate areas of concern by using one service per container. That service may fork into multiple processes (for example, Apache web server starts multiple worker processes). It’s ok to have multiple processes, but to get the most benefit out of Docker, avoid one container being responsible for multiple aspects of your overall application. You can connect multiple containers using user-defined networks and shared volumes".

Therefore, at first, I will cover the way of monitoring the docker container from the host system itself. 
Afterwards, there is also a paragraph, where I showcase the theoretical implementation of agent as a part of docker container itself.


### Configuring agent to monitor docker events
Documentation used: 
* https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html
* https://documentation.wazuh.com/current/user-manual/capabilities/container-security/use-cases.html
* https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html#enable-wazuh-docker-listener

Infrastructure setup: 
* Ubuntu 20.04 hosting Wazuh - Server machine
* Ubuntu 20.04 hosting other docker containers - Client machine

#### Configure Wazuh agent on client
* https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html#enable-wazuh-docker-listener

There is a default module to monitor some  docker related activity. To use it, it should be first enabled. To do so, the next part should be added into /var/ossec/etc/ossec.conf of server:
```
<wodle name="docker-listener">
  <disabled>no</disabled>
</wodle>
```
All configurations should be also possible to edit via Wazuh browser management. For example, to make a configuration for all servers of the specific group: 
``Endpoint Groups -> Edit group configurations (actions tab for specific group)``

For server configuraiton (not applicable here):
``Server management -> Settings -> Edit configuration`` and add the <wodle> mentioned above.

However, as per testing this on specific machine, I have decided to to this on the machine itself: ``sudo nano /var/ossec/etc/ossec.conf`` and add the required configuration. 

Agent should be rebooted after every change made to configuration. However, I will do this after I finish configuring everything.

#### Enabling Wazuh agent to receive remote commands from Wazuh server
This is done due to Wazuh having disabled command execution by default.
```
echo "logcollector.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf
systemctl restart wazuh-agent
```

#### Monitoring container runtime
* https://documentation.wazuh.com/current/user-manual/capabilities/container-security/use-cases.html

Docker container runtime is stored under ``/var/lib/docker/containers/<CONTAINER_ID>/<CONTAINER_ID>-json.log`` by default. It is useful to monitor this place as well. 
To do so, the next configuration should be added into ``/var/ossec/etc/ossec.conf`` file:
```
<localfile>
  <log_format>syslog</log_format>
  <location>/var/lib/docker/containers/*/*-json.log</location>
</localfile>
```
This was also done manually by editing configuration file on the client.

Now Wazuh agent should be restarted to apply the changes:
``systemctl restart wazuh-agent``


#### Installing docker on client
It is also required to have a docker on the client to run the actual containres.
```
apt install python3 python3-pip
pip3 install docker==7.1.0 urllib3==2.2.2 requests==2.32.2
```

### Wazuh Server configuration
Several decoders were added to the server via Wazuh visual interface:
``Server management -> Decoders -> Custom deecoders -> local_decoders.xml``
All decoders will be saved under decodes/ section of this Git page.

```
<decoder name="web-accesslog-docker">
  <parent>json</parent>
  <type>web-log</type>
  <use_own_name>true</use_own_name>
  <prematch offset="after_parent">^log":"\S+ \S+ \S+ \.*[\S+ \S\d+] \.*"\w+ \S+ HTTP\S+" \d+</prematch>
  <regex offset="after_parent">^log":"(\S+) \S+ \S+ \.*[\S+ \S\d+] \.*"(\w+) (\S+) HTTP\S+" (\d+)</regex>
  <order>srcip,protocol,url,id</order>
</decoder>

<decoder name="json">
  <parent>json</parent>
  <use_own_name>true</use_own_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```


#### Testing
* https://documentation.wazuh.com/current/user-manual/capabilities/container-security/use-cases.html
The next testing will trigger alerts for interaction with containers:
```
docker run -d --name test-container httpd
docker pause test-container
docker unpause test-container
docker stop test-container
docker rm test-container
docker rmi httpd
```

The next event will monitor different type of attacks:
```
docker run --name test-container -p 80:80 -d nginx
curl -XGET "http://<WEB_IP_ADDRESS>/users/?id=SELECT+*+FROM+users";
```
This also works for DVWA container. It could be done using curl, or simply using web interface.

DVWA installation:
```
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

#### Screenshots
Triggering docker actions from configured Docker view:
![Alt text](/screenshots/docker_actions_1.jpg?raw=true "Docker actions view 1")

Triggering docker actions from log view:
![Alt text](/screenshots/docker_actions_2.jpg?raw=true "Docker actions view 2")

SQL Injection Attemp and (the last event) successful SQL Injection events:
![Alt text](/screenshots/sql_injection_attempt_1.jpg?raw=true "SQL Injection Attempt and Initial Access success event")

Successfull SQL Injection from DVWA (view from DVWA window itself):
![Alt text](/screenshots/sql_injection_via_dvwa_1.jpg?raw=true "Successfull SQL Injection Attempt via DVWA from browser")

View of different attack vectors that are available by default:
![Alt text](/screenshots/other_attack_vecotrs_example.jpg?raw=true "Example of other Attack vecotrs available")

### Configuring vulnerability monitoring
Currently, Wazuh intergration with docker does not provide any out-of-the-box solutions for vulnerability monitoring (in case we do not install wazuh agent to the docker itself). 
Therefore, I have investigated different options that are available online. The three most commonly discussed are:
* Clair
* Anchore
* Trivy

These tools have different type of functionality that they propose. Trivy seems to be the most suiting the need of vulnerablity scanning. This tool should find and identify vulnerabilities, misconfigurations, secrets, SBOM in containers.
* More about Trivy: https://github.com/aquasecurity/trivy

First, I have installated Trivy on the client machine that is running docker containers:
```
wget https://github.com/aquasecurity/trivy/releases/download/v0.18.3/trivy_0.18.3_Linux-64bit.deb
sudo dpkg -i trivy_0.18.3_Linux-64bit.deb
```

By default, Trivy outputs an informative table into command line interface. However, as it is planned to use it integrated into Wazuh, I have chosen the next solution:
1. Run Trivy with next parameters: ``--format json --output /var/ossec/logs/trivy-results.json``
This will make the format of scan into a json and send it to the Wazuh log direcotry. From there, the log can be grabbed by Wazuh.
2. For Wazuh to check this log file, the next configuration changes were done on the client configuration ``/var/ossec/etc/ossec.conf``:
```
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/trivy-results.json</location>
</localfile>
```
And Wazuh agent should be restarted to apply the changes:
``systemctl restart wazuh-agent``

3. To automatize the process, simple schedule task could be written. The scheduled task/ cron may run the script or the command itself. 
* Example script (for production, I would suggest making script that goes over all docker containers found on the host)
```
#!/bin/bash

# Define the target to scan (e.g., a Docker image or a directory)
TARGET="vulnerables/web-dvwa"

trivy image --format json --output /var/ossec/logs/trivy-results.json $TARGET 2>&1
```
* Example cron
```
0 2 * * * /bin/bash ~/run_trivy.sh
```

4. The Wazuh should now collect json and send it to the server. To setup proper alering on Wazuh, decoders and rules may be neccassary. It could be also useful to rewrite the output of json.
To confirm that the json is collected by the Wazuh, we can run the next command: ``cat /var/ossec/logs/ossec.log | grep trivy-results.json``

Screenshot of the output:
![Alt text](/screenshots/trivy_results_collect.jpg?raw=true "Prove that Wazuh Agent collected the logs")

Since this is a PoC, I have skipped developing custom decoder logic on the Wazuh side.

5. Results of scan: Trivy json output for DVWA is placed under trivy/ folder of this Git (zipped into trivy-results.zip). 


### Configure docker container deployment with agent
This section explains the theoretical way of deployment of Wazuh agent directly to the docker container itself.
In theory, it could be possible to run Wazuh agent on every single container itself. For example, it is possible to create a Dockerfile, which will run the next block of code when starting DVWA:
```
# Set environment variables for Wazuh agent configuration
ENV WAZUH_MANAGER='192.168.75.133'
ENV WAZUH_AGENT_GROUP='container,default'
ENV WAZUH_AGENT_NAME='docker_client_1'

# Update the package list and install required packages
RUN apt-get update && \
    apt-get install -y wget dpkg lsb-release adduser nginx supervisor && \
    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.1-1_amd64.deb && \
    dpkg -i ./wazuh-agent_4.8.1-1_amd64.deb && \
    apt-get install -f -y && \
    rm -rf /var/lib/apt/lists/* /wazuh-agent_4.8.1-1_amd64.deb && \
    # Check the installation path of the Wazuh agent
    find / -name "wazuh-agent" 2>/dev/null
```
However, I was unable to prove this in practice using DVWA pacakge, since, as mentioned before, DVWA has an initially a broken setup. 
I have tried to manually add updated debian images to the list. However, running ``apt-get update && apt-get install wget`` will still fail. 
After some investigations, it seems that there are missing core libraries, for example a missing shared library libcrypt.so.1.
Unfortunately, from my point of view, setting up Wazuh agent for this particular packagee is too complex. As mentioned above, it is also a non-standart pracise to install several different applications under one docker container.
Installing Wazuh agent as another container will not solve the issue, since agent should be installed on the same OS as other service.

## After view
![Alt text](/screenshots/wazuh_view_1.jpg?raw=true "Wazuh view 1")
![Alt text](/screenshots/wazuh_view_2.jpg?raw=true "Wazuh view 2")

