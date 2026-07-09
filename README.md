# Automated Cloud SOC: Threat Detection & Incident Response Pipeline

## Project Objective
I wanted to get hands-on with building and automating a cloud-based Security Operations Centre (SOC) in Microsoft Azure. For this project, I set up a temporary (ephemeral) infrastructure pipeline that intentionally exposed a vulnerable Linux honeypot to the open internet. From there, I funnelled the telemetry into a centralised SIEM and set up an automated, network-level response using SOAR principles.

Instead of treating servers like permanent fixtures, I treated them as disposable assets. I built, tested, and systematically tore down the entire environment. It was a great way to practice real-world threat mitigation while keeping a close eye on cloud spend (because cost optimisation is key!).

## Architecture Diagram

![Uploading 3616042815537316202.jpg…]()


## Technology Stack & Core Concepts
* **Cloud Provider:** Microsoft Azure
* **Infrastructure:** Ubuntu Server (Honeypot VM), Virtual Networks (VNet), Network Security Groups (NSG)
* **Telemetry & Ingestion:** Azure Monitor Agent (AMA), Data Collection Rules (DCR), Linux Syslog
* **SIEM Platform:** Microsoft Sentinel, Log Analytics Workspace (LAW)
* **SOAR Automation:** Azure Logic Apps, Azure Resource Manager (ARM) API
* **Detection Engineering:** Kusto Query Language (KQL)
* **Access Control:** System-Assigned Managed Identities, Role-Based Access Control (RBAC)

## Phase 1: Infrastructure and Telemetry Ingestion
First up, I spun up an Ubuntu Linux VM and configured a highly permissive Network Security Group (NSG) rule to allow inbound SSH traffic (port 22) from anywhere. The goal was to deliberately attract automated scanners and brute-force attempts. 

To pull all that network telemetry into one place, I deployed the Azure Monitor Agent to the VM. Using Data Collection Rules, I filtered the logs to only grab authentication events (`auth` and `authpriv` Syslog facilities) to keep storage costs down. These events were then streamed straight into a Log Analytics Workspace hooked up to Microsoft Sentinel.

## Phase 2: Detection Engineering via KQL
With the auth logs successfully parsing into the SIEM, it was time to write some custom detection logic using Kusto Query Language (KQL). The aim here was to filter out the background noise of routine scanning and zero in on aggressive brute-force attacks.

I set up a Scheduled Analytic Rule in Sentinel to trigger a security incident if a single IP address racked up more than 10 failed login attempts in a short timeframe.

```kusto
Syslog
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage contains "Failed password"
| extract @"from ([\d\.]+)", 1, SyslogMessage
| summarize FailedAttempts = count() by AttackerIP = extract1
| where FailedAttempts > 10
```

## Phase 3: Automated Incident Response (SOAR)
To shut down the attacks as quickly as possible, I built a SOAR playbook using Azure Logic Apps.

Whenever the Sentinel rule catches a brute-force attack and generates an incident, the Logic App automatically kicks in. It parses the event data, isolates the attacker's IP address, and uses a System-Assigned Managed Identity (with just enough network permissions) to talk directly to the Azure Resource Manager API.

The Logic App essentially injects a dynamic JSON payload into the VM's Network Security Group, instantly creating a high-priority 'deny' rule that blocks the malicious IP right at the front door.
<img width="2816" height="1536" alt="diagram" src="https://github.com/user-attachments/assets/a02a61c5-17d9-44e0-ab64-a8e11ca55324" />

```json
{
  "properties": {
    "protocol": "*",
    "sourcePortRange": "*",
    "destinationPortRange": "*",
    "sourceAddressPrefix": "@{items('For_each')}", 
    "destinationAddressPrefix": "*",
    "access": "Deny",
    "priority": 100,
    "direction": "Inbound"
  }
}
```
## Project Takeaways & Engineering Outcomes

* **Bridging Theory and Practice:** This project was a brilliant way to take foundational security concepts and apply them in a live cloud environment. It went beyond just understanding the theory to actually architecting, deploying, and monitoring a functional threat mitigation pipeline in Azure.
* **Modern Enterprise Automation (SOAR):** I got hands-on with Security Orchestration, Automation, and Response. By hooking up Logic Apps with the Azure Resource Manager API, I replaced manual incident response with real-time, programmatic network defence—exactly how it is done in mature SOCs.
* **Detection Engineering:** Rather than relying on generic, out-of-the-box alerts, I wrote custom parsing and detection logic using KQL. It was a great exercise in turning noisy, raw log data into actionable security intel.
* **Cloud Cost Optimisation & Lifecycle Management:** Embracing the 'ephemeral infrastructure' mindset meant I could build, test, and tear down this entire enterprise-grade setup while keeping cloud spend near zero. It was a solid lesson in cost-conscious resource management.
