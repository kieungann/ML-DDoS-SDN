# BUILDING A MACHINE LEARNING MODEL FOR DDOS ATTACK DETECTION IN SOFTWARE-DEFINED NETWORKING ARCHITECTURE

## Overview
This project focuses on building a machine learning model to detect Distributed Denial of Service (DDoS) attacks in a Software-Defined Networking (SDN) architecture. The goal is to develop an intelligent and flexible security solution that leverages advanced machine learning techniques to identify and mitigate DDoS attacks effectively.

**Instructors**: ThS. Nguyễn Khánh Thuật, ThS. Văn Thiên Luân  
**Project Duration**: February 2025 - June 2025  
**Contributors**:  
- Võ Huỳnh Kiều Ngân - 22520938  

## Table of Contents
- [Objectives](#objectives)
- [Architecture and Scenario](#architecture-and-scenario)
- [Technologies](#technologies)
- [Simulation Environment](#simulation-environment)
- [Performance Metrics](#performance-metrics)
- [Expected Results](#expected-results)
- [References](#references)

## Objectives 
This project aims to develop a machine learning model to detect Distributed Denial of Service (DDoS) attacks within a Software-Defined Networking (SDN) architecture. The key objectives include:
- Creating a smart and flexible security solution by integrating advanced machine learning with SDN.
- Optimizing the deployment of machine learning models tailored to SDN's unique characteristics.
- Researching DDoS attack types, suitable machine learning algorithms, SDN architecture, and network flow data related to DDoS.

## Architecture and Scenario 
<p align="center">
  <img src="https://github.com/user-attachments/assets/e8fc6ff1-6c20-4c0d-99fc-84e31a6c72a9" alt="mô hình quy trình hoạt động" width="600">
</p>

The project leverages an SDN architecture with a centralized controller managing network traffic. The scenario includes:
- A simulated network with normal hosts (generating TCP, UDP, ICMP, HTTP traffic) and attack hosts (simulating SYN flood, UDP flood, ICMP flood).
- The architecture integrates a traffic collector to log network data, a machine learning-based DDoS detector, and a Mininet topology for simulation.
- The system uses OpenFlow protocol to monitor and control flow tables, detecting anomalies in real-time.

## Technologies 
- **SDN Controller**: Ryu
- **Machine Learning**: Scikit-learn (Random Forest, SVM, MLP)
- **Network Simulation**: Mininet
- **Packet Analysis**: Scapy
- **Programming Language**: Python

## Simulation Environment
<p align="center">
  <img src="https://github.com/user-attachments/assets/6dbd9ad6-0e51-4925-900a-080f976d6bbe" alt="Mininet Topology Diagram" width="600">
</p>

The simulation environment is set up using Mininet with the following configuration:
- **Topology**: A network with switches (s1, s2, s3), normal hosts (h1-h5), attack hosts (a1-a5), and a server.
- **Controller**: Ryu running on localhost (port 6653) with OpenFlow 1.3 protocol.
- **Data Collection**: Traffic is logged to `live_traffic.csv` in the `data/processed/` directory of the project.
- **Attack Simulation**: Tools like `hping3` and `iperf` generate attack and normal traffic.

## Performance Metrics 
The project evaluates the model using the following metrics:
- **Accuracy**: Percentage of correctly classified instances.
- **Precision, Recall, F1-Score**: To assess the balance between false positives and false negatives.
- **Detection Latency**: Average time to detect an attack (measured in milliseconds per sample).
- **Throughput**: Network performance under attack conditions.

## Expected Results 
- The GRU-RNN model is expected to achieve approximately 89% accuracy in detecting DDoS intrusions, based on findings from [14].
- A combined approach using Network Behavior Analysis (NBA), Distributed Intrusion Detection System (DIDS), and Role-Based Access Control (RBAC) is expected to reduce response times and maintain network stability.
- The Random Forest model is anticipated to provide robust detection with low latency, validated through cross-validation and test datasets, consistent with [6].

## References 
- [1] Cisco, "Cisco Annual Internet Report (2018–2023)," 2020, [Online]. Available: https://www.cisco.com/c/en/us/solutions/collateral/executive-perspectives/annual-internet-report/white-paper-c11-741490.html.
- [4] Pérez-Díaz et al., "A Flexible SDN-based Architecture for Identifying and Mitigating Low-Rate DDoS Attacks using Machine Learning," *IEEE Access*, 2020.
- [5] K. Jiang et al., "Network Intrusion Detection Combined Hybrid Sampling With Deep Hierarchical Network," *IEEE Access*, 2020.
- [6] N. S. Musa et al., "Machine Learning and Deep Learning Techniques for DDoS Anomaly Detection in SDN," *IEEE Access*, 2024.
- [10] D. Kreutz et al., "Software-Defined Networking: A Comprehensive Survey," *Proceedings of the IEEE*, 2015.
- [14] T. A. Tang et al., "Deep Recurrent Neural Network for Intrusion Detection in SDN-based Networks," *NetSoft 2018*.
- [15] Bawany et al., "DDoS Attack Detection and Mitigation Using SDN," *Arabian Journal for Science and Engineering*, 2017.
