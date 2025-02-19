---
layout: archive
title: "CV"
permalink: /cv/
author_profile: true
redirect_from:
  - /resume
---

{% include base_path %}

[**Download my latest CV**](https://jianwei.me/files/CV_Jianwei_Huang.pdf)

## Education
* **Texas A&M University, College Station, Texas**  
  *Ph.D. in Computer Science* (09/2019 - 12/2025, expected)  
* **Wuhan University, Wuhan, China**  
  *Bachelor of Engineering, Computer Science* (09/2014 - 06/2018)

## Work Experience
* **SRI International, Menlo Park, CA, USA**  
  *Summer Intern* (05/2020 - 08/2020)  
  - Conducted research on COVID app security.

* **Texas A&M University, Texas, USA**  
  *Teaching Assistant*  
  - CSCE 465: Computer & Network Security  
  - CSCE 451/652: Software Reverse Engineering  
  - CSCE 477/703: Cybersecurity Risk  

## Selected Project Experience

### **Blackbox Fuzzing on Web Applications with LLM Assistance (Ongoing)**
- Designed an LLM-driven framework for client-side fuzzing of web applications.
- Evaluating the framework on open-source web applications and conducting large-scale testing on Docker Hub images.

### **Security Analysis on Ethereum Name Service (ENS)**
- Discovered a unique security vulnerability in ENS.
- Identified inconsistencies in ENS domain normalization across popular wallets, dApps, and ENS controllers.
- Assessed security risks in 300+ widely used dApps and collaborated with vendors to mitigate them.

### **Security Analysis of One-Time Tokens in Web Applications (In Submission)**
- Identified discrepancies between RFC specifications and real-world implementations.
- Defined the lifecycle and essential security properties of One-Time Tokens in web applications.
- Developed an automated tool to detect and assess the security properties of One-Time Tokens.
- Evaluated the security of One-Time Tokens in popular Node.js web applications, uncovering 20+ vulnerabilities.

### **Zero Trust Framework Design and Implementation**
- Developed `sysflow`, a Zero Trust Framework enabling unified, dynamic, and fine-grained security controls for system resources.
- Implemented two key applications leveraging `sysflow`.
- **Code:** [sysflow-controller](https://github.com/successlab/sysflow-controller) & [sysflow-dataplane](https://github.com/successlab/sysflow-dataplane)

### **Security Framework Based on Service Worker**
- Contributed to the development of a Service Worker-based security framework to enhance website security on the client side.
- Designed and implemented multiple security applications within the framework.
- **Code:** [swapp](https://github.com/successlab/swapp)

### **Hidden Property Abusing in the Node.js Ecosystem**
- Developed an automated tool to detect hidden properties in Node.js programs.
- Evaluated the tool on over 70 widely used Node.js libraries.
- **Code:** [Lynx](https://github.com/xiaofen9/Lynx)

### **Security Analysis of SDN Controllers**
- Conducted security analysis of the top five open-source SDN controllers.
- Discovered approximately 10 vulnerabilities related to unintended data dependency creation.
- Developed a tool to identify sensitive methods in SDN controllers and generate data dependencies for targeted attacks.

### **iOS Application Analysis**
- Created an automated tool to identify key functions related to specific features in iOS applications.
- Uncovered critical vulnerabilities in WeChat SDK and Meituan.
- **Code:** [Corgi](https://github.com/cl0udz/Corgi)

### **Moving Target Defense System in SDN**
- Designed an algorithm to map the hierarchical structure of all hosts within an intranet.
- Developed an obfuscation system for SDN environments to enhance security.