# **Mendelsohn Kernel Standard (MKS) v2.0**

**A normative architecture for building reliable, auditable Institutional Multi-Agent Systems.**

"Agents are not tools. They are institutional actors."

## **1.0 The Problem: Value Alignment**

Most AI agent frameworks focus on **Capability**: *Can the agent do the task?*

MKS focuses on **Governance**: *Should the agent do the task, and did it follow our values?*

In high-stakes environments—whether that is Medical, Financial, or Theological—a hallucination is not a "bug"; it is a violation of trust. The **Principal-Agent Problem** dictates that if you have to double-check every output for safety, the agent creates more work than it saves.

## **2.0 The Solution: MKS Architecture**

MKS solves this by wrapping probabilistic LLMs (Kernels) in a deterministic runtime (Orchestrator).

### **2.1 The Core Components**

1. **Kernels (The Cells):** The atomic unit of agency. Not just a prompt, but a state object with Identity, Axioms, and Gates.  
2. **Orchestrator (The Hardware):** A deterministic Python runtime. It parses logic gates and enforces rules. It does not "think"; it obeys.  
3. **Culture Stack (The Rules):** A hierarchy of norms.  
   * \[0\] Global: Core Values/Safety (Overrides all).  
   * \[1\] Domain: Contextual Rules (e.g., Tone, Style).  
   * \[2\] Local: Task-specific prompt instructions.  
4. **Immune System:** A **Generator-Critic** loop. No worker output touches the outside world without passing an Auditor Kernel check.

## **3.0 Quick Start (Wind Tunnel)**

The mks\_core.py file contains a reference implementation and a "Wind Tunnel" simulation using a **Theological Integrity** scenario.

### **Prerequisites**

* Python 3.8+  
* No external dependencies required for the core (Standard Lib only).

### **Run the Simulation**

python mks\_core.py

### **What You Will See**

The simulation runs a scenario where a PULPIT\_CO\_PILOT agent tries to draft content.

1. **Attempt 1:** The agent drafts content that is readable but **Theologically Unsound** (Axiom Violation).  
   * *Result:* The **Auditor** rejects it immediately.  
2. **Attempt 2:** The agent fixes the theology, but writes it at a **PhD Level** (Gate Violation: Accessibility).  
   * *Result:* The **Orchestrator** blocks it (Too complex for general audience).  
3. **Attempt 3:** The agent simplifies the language while maintaining truth.  
   * *Result:* **PASS**.

## **4.0 The Protocol**

Kernels communicate via strict **MKS\_MESSAGE** envelopes. No unstructured chat.

{  
  "id": "uuid-123",  
  "from": "PULPIT\_KERNEL",  
  "type": "WORKER\_OUTPUT",  
  "payload": {   
    "readability\_grade": 8.5,  
    "orthodoxy\_check": true   
  },  
  "logic\_trace": { "reasoning": "Synthesizing theological concepts..." }  
}

## **5.0 About the Author**

**Focus Flow Systems** applies institutional economics and systems design to AI governance. We believe the hard part of AI isn't the code—it's the constraints.

* **Status:** Normative Specification  
* **Version:** 2.0 (SPR\_Native)  
* **License:** Apache 2.0
