# Mini-SOC — Security Monitoring & Incident Detection Platform

A lightweight, self-contained Security Operations Center (SOC) platform built with Python for security log monitoring, threat detection, alert management, incident investigation, and security reporting.

Mini-SOC demonstrates a complete defensive security workflow:

**Detection → Alert → Investigation → Response → Reporting**

The project is designed as an educational and portfolio-focused SOC environment that allows security analysts and students to explore common security monitoring and detection concepts without requiring real network infrastructure or external services.

---

## Overview

Mini-SOC collects security logs, normalizes them into a common event structure, applies rule-based detection and statistical anomaly detection, generates severity-scored alerts, and provides a web-based dashboard for investigation and incident management.

The platform includes a synthetic log generator that produces realistic Linux, Windows, and firewall events, including predefined attack scenarios. This makes the project fully self-contained and easy to demonstrate in a local environment.

No real network connections are required for the demo environment.

---

## Architecture

```text
┌───────────────────────────────────────────────┐
│              Synthetic / Sample Logs          │
│       Linux · Windows · Firewall Events       │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
              ┌───────────────────┐
              │   Log Collector   │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ Log Normalization │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ Detection Engine  │
              └─────────┬─────────┘
                        │
                 ┌──────┴──────┐
                 ▼             ▼
          ┌────────────┐ ┌───────────────┐
          │   Rules    │ │    Anomaly    │
          │  Detection │ │   Detection   │
          └──────┬─────┘ └───────┬───────┘
                 │               │
                 └───────┬───────┘
                         ▼
                ┌──────────────────┐
                │   Alert Engine   │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │   SOC Dashboard  │
                └────────┬─────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
       ┌─────────────┐       ┌──────────────┐
       │ Investigation│       │   Incidents  │
       │   & Search   │       │  Management  │
       └─────────────┘       └──────┬───────┘
                                    │
                                    ▼
                            ┌────────────────┐
                            │    Reports     │
                            └────────────────┘