# GuardianFlow AI Architecture

## Project Vision

GuardianFlow AI is an AI-powered Security Operations Center (SOC) platform designed to monitor endpoint activity in real time, detect potential cyber threats, analyze security events, and assist security analysts through AI-driven explanations and recommendations.

Unlike the MVP version, GuardianFlow AI Version 1.0 will collect real system events instead of simulated data, enabling continuous monitoring and scalable threat detection across multiple endpoints.

## Core Principles

1. Real-time over simulated data
   - All security events should originate from actual system activity whenever possible.

2. Modular architecture
   - Each component should have a single responsibility and communicate through well-defined interfaces.

3. Scalability
   - The system should support multiple endpoint agents without requiring architectural changes.

4. AI-assisted analysis
   - AI should explain and summarize security events, but it should not replace deterministic threat detection.

5. Extensibility
   - New log sources, detection rules, and AI capabilities should be easy to add without modifying existing modules.

6. Maintainability
   - The project should remain organized, documented, and easy for new contributors to understand.

   
   
   ## System Components

### 1. Endpoint Agent

Runs on every monitored endpoint.

Responsibilities:
- Collect Windows Event Logs
- Collect process information
- Collect network activity
- Collect file system events
- Convert collected data into a standard JSON format
- Send events securely to the GuardianFlow Server

The agent is responsible only for data collection.
It does not perform threat detection or AI analysis.

---

### 2. GuardianFlow Server

Acts as the central processing unit of the platform.

Responsibilities:
- Receive events from endpoint agents
- Validate incoming data
- Store events
- Forward events to the detection engine
- Notify connected dashboards

---

### 3. Detection Engine

Analyzes incoming events and determines whether they indicate suspicious activity.

Responsibilities:
- Rule-based threat detection
- Severity classification
- Threat categorization
- MITRE ATT&CK mapping (future)

---

### 4. AI Analysis Engine

Provides human-readable explanations for detected threats.

Responsibilities:
- Explain alerts
- Recommend mitigation steps
- Summarize incidents
- Assist SOC analysts

---

### 5. Dashboard

Provides a real-time interface for monitoring the environment.

Responsibilities:
- Display live events
- Display alerts
- Show endpoint status
- Display AI-generated explanations
- Visualize incident history

## Data Flow

The overall flow of data within GuardianFlow AI is as follows:

Windows Endpoint
        │
        ▼
Guardian Agent
        │
        ▼
GuardianFlow Server
        │
        ├──────────────► Database
        │
        ▼
Detection Engine
        │
        ▼
AI Analysis Engine
        │
        ▼
WebSocket Server
        │
        ▼
Dashboard


### Flow Description

1. The Guardian Agent continuously monitors the endpoint.

2. The agent converts collected events into a standardized JSON format.

3. Events are securely transmitted to the GuardianFlow Server.

4. The server stores every event in the database.

5. The Detection Engine analyzes incoming events.

6. If suspicious activity is detected, an alert is generated.

7. The AI Analysis Engine explains the alert and recommends actions.

8. The Dashboard receives live updates through WebSockets.


## Refactoring Plan

The MVP implementation will not be discarded.

Instead, every existing module will be evaluated and classified into one of three categories:

### Keep
Modules that can be reused with little or no modification.

### Refactor
Modules that contain useful logic but require restructuring.

### Replace
Modules that were created specifically for the MVP and should be rewritten for Version 1.0.


## Development Roadmap

### Phase 1 - Foundation
- Create a clean project architecture
- Refactor the MVP codebase
- Standardize data models
- Prepare configuration management

### Phase 2 - Endpoint Agent
- Read Windows Event Logs
- Collect endpoint information
- Send events to the server
- Implement heartbeat monitoring

### Phase 3 - Server
- Receive endpoint events
- Store events in a database
- Implement WebSocket communication
- Support multiple endpoint agents

### Phase 4 - Detection Engine
- Rule-based threat detection
- Severity classification
- Threat correlation
- MITRE ATT&CK mapping

### Phase 5 - AI Engine
- Explain detected threats
- Recommend mitigation
- Summarize incidents
- Generate investigation reports

### Phase 6 - Dashboard
- Live event monitoring
- Endpoint management
- Incident timeline
- Search and filtering

### Phase 7 - Future Enhancements
- Linux agent
- Docker monitoring
- Cloud log collection
- Sigma rule support
- Threat Intelligence integration
- Machine Learning detection