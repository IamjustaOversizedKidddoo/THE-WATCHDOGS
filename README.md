<pre>
<span style="color:red">
████████╗██╗  ██╗███████╗    ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗██████╗  ██████╗  ██████╗ ███████╗
╚══██╔══╝██║  ██║██╔════╝    ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔═══██╗██╔════╝ ██╔════╝
   ██║   ███████║█████╗      ██║ █╗ ██║███████║   ██║   ██║     ███████║██║  ██║██║   ██║██║  ███╗███████╗
   ██║   ██╔══██║██╔══╝      ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║██║  ██║██║   ██║██║   ██║╚════██║
   ██║   ██║  ██║███████╗    ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝███████║
   ╚═╝   ╚═╝  ╚═╝╚══════╝     ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝
</span>
</pre>

### A Multi-Agent Cybersecurity Operations Platform
### Visualized as a Living Digital Security Office

<p>
  <strong>Reconnaissance • Discovery • Validation • Reporting • Orchestration</strong>
</p>

<p>
  <em>What if your cybersecurity agents didn't just run in terminals — what if you could actually see them working?</em>
</p>

<br>

![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red?style=for-the-badge)
![Multi Agent](https://img.shields.io/badge/Architecture-Multi--Agent-black?style=for-the-badge)
![White Hat](https://img.shields.io/badge/Use-Authorized%20Security-red?style=for-the-badge)
![Human in the Loop](https://img.shields.io/badge/Human--in--the--Loop-Enabled-black?style=for-the-badge)

</div>

---

# 🐺 What is THE WATCHDOGS?

**THE WATCHDOGS** is an experimental multi-agent cybersecurity platform exploring how autonomous security agents can work together as a coordinated security team — while their activity is represented through a **living pixel-art office**.

Instead of watching a collection of terminals and logs, the operator sees agents physically moving through an office, going to different workstations, performing tasks, communicating, waiting for decisions, and responding to real backend events.

The core idea:

> **The pixel office is not the cybersecurity system.**
>
> **It is the visual interface to the cybersecurity system.**

---

# ⚡ The Concept

Traditional security automation often looks like:

```text
TARGET
  ↓
TOOL
  ↓
OUTPUT
  ↓
ANOTHER TOOL
  ↓
LOGS
  ↓
REPORT

THE WATCHDOGS explores a coordinated multi-agent model:

┌─────────────────────┐
                         │       HUMAN         │
                         │      OPERATOR       │
                         └──────────┬──────────┘
                                    │
                             APPROVAL / CONTROL
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    ORCHESTRATOR     │
                         │      /michael       │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
         /jonathan               /chris               /rooster
           RECON               DISCOVERY              AI SECURITY
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    │
                                    ▼
                              REPORTING
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    PIXEL OFFICE     │
                         │  LIVE VISUALIZATION │
                         └─────────────────────┘

The objective is not simply to automate individual security tools.

The objective is to explore a coordinated security workforce made up of specialized agents.


---

🏢 The Living Security Office

The defining feature of THE WATCHDOGS is its office visualization.

Every agent can have:

a workstation

a physical location

a set of states

movement between locations

task-specific animations

communication events

waiting states

approval states


An agent might move through the office like this:

DESK
  ↓
RECON STATION
  ↓
WORKING
  ↓
MEETING / COMMUNICATION
  ↓
VALIDATION
  ↓
REPORTING

The office is designed to answer three questions immediately:

> Who is working?



> What are they doing?



> Does anything require my attention?




---

🧠 Real Backend Activity → Visual Behavior

The most important distinction is that the office should not simply play random animations.

The architecture connects the visual layer to real backend activity.

REAL AGENT / PROCESS
        ↓
    AGENT STATE
        ↓
     EVENT
        ↓
  OFFICE STATE
        ↓
CHARACTER MOVEMENT
        ↓
    ANIMATION

For example:

Recon starts
    ↓
Agent becomes active
    ↓
Character walks to the recon station
    ↓
Character begins working
    ↓
Recon completes
    ↓
Agent sends results
    ↓
Next agent receives the task

This makes the office a visual representation of what the system is actually doing.


---

👥 Specialized Watchdogs

The project is based around specialized agents rather than one AI attempting to perform every part of a security operation.

/jonathan

Reconnaissance

Responsible for the reconnaissance stage of an authorized security workflow.

Conceptually:

Target
  ↓
Reconnaissance
  ↓
Discovered Information
  ↓
Next Agent


---

/chris

Discovery & Validation

Responsible for investigating and validating potential security findings.

Conceptually:

Candidate
  ↓
Investigation
  ↓
Validation
  ↓
Evidence
  ↓
Finding


---

/rooster

AI / LLM Security

A specialized security agent intended for controlled testing of AI-powered targets.

The project specifically explores using a separate local AI target for safe experimentation.

Potential areas include:

prompt injection

jailbreak resistance

instruction-boundary testing

unsafe model behavior

AI application security



---

/michael

Orchestrator

The coordination layer responsible for routing work between agents.

Conceptually:

/michael
                   ORCHESTRATOR
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
     /jonathan       /chris       /rooster
        RECON       VALIDATION    AI SECURITY

The orchestrator represents the "brain" above the individual agents.


---

🐝 The Hive

At the center of THE WATCHDOGS is the concept of a Hive.

The Hive provides a coordination and communication layer between agents.

HIVE
                          │
            ┌─────────────┼─────────────┐
            │             │             │
            ▼             ▼             ▼
          TASKS        MESSAGES      FINDINGS
            │             │             │
            └─────────────┼─────────────┘
                          │
                          ▼
                     ORCHESTRATOR

Agents can communicate through file-based mailboxes and shared project state.

This allows one agent to hand work to another without every agent needing to understand the entire operation.


---

📨 Agent Communication

A simplified communication flow:

/jonathan
    │
    │ Recon completed
    ▼
 MAILBOX
    │
    ▼
 /michael
    │
    │ Route candidate for validation
    ▼
 /chris

This creates a chain of specialized work instead of isolated processes.


---

🔐 Human-in-the-Loop

THE WATCHDOGS is designed around human oversight.

Autonomous agents should not automatically receive unrestricted authority simply because they are capable of performing an action.

The intended model is:

Agent proposes action
        ↓
Authorization check
        ↓
Scope check
        ↓
Risk / policy check
        ↓
Human approval
        ↓
┌───────────────┐
│               │
▼               ▼
APPROVE        DENY
│               │
▼               ▼
CONTINUE       STOP

The project explores:

autonomy levels

execution budgets

circuit breakers

human escalation

approval queues


These controls are intended to prevent an autonomous agent from operating beyond its authorized boundaries.


---

🎯 Authorization First

THE WATCHDOGS is intended for authorized cybersecurity work.

The system should distinguish between:

> "I can technically reach this system."



and:

> "I am authorized to test this system."



An authorization registry can define the scope of a target.

Example:

target:
  name: authorized-lab

  in_scope:
    - localhost:3000

  verified_by: human

  last_verified: YYYY-MM-DD

  live_tool_invocation_authorized: false

The registry provides an explicit boundary for security operations.


---

🚨 Fail Closed

When authorization, scope, or policy information is uncertain:

┌─────────────────────────┐
│       UNCERTAINTY       │
└────────────┬────────────┘
             │
             ▼
           STOP

The system should not assume authorization.


---

🧪 The Laboratory

Development should begin in a controlled environment rather than against arbitrary external systems.

Recommended intentionally vulnerable targets include:

Target	Purpose

OWASP Juice Shop	Web application security testing
DVWA	Vulnerable web application testing
WebGoat	Web security education
Metasploitable2	Network / infrastructure testing
Local AI target	AI / LLM security testing


A basic laboratory can look like:

AUTHORIZED LAB
                    │
        ┌───────────┼───────────┐
        │           │           │
        ▼           ▼           ▼
   JUICE SHOP     DVWA      WEBGOAT
        │

</div>

---

# 🐺 What is THE WATCHDOGS?

**THE WATCHDOGS** is a project exploring how autonomous cybersecurity agents can work together as a coordinated security team — while their activity is represented through a **living pixel-art office**.

Instead of looking at a collection of terminals and logs, the operator sees agents physically moving through an office, going to different workstations, performing tasks, communicating, waiting for decisions, and responding to real backend events.

The core idea is:

> **The pixel office is not the cybersecurity system.**
>
> **It is the visual interface to the cybersecurity system.**

---

# ⚡ The Concept

Traditional security automation often looks like:

```text
TARGET
  ↓
TOOL
  ↓
OUTPUT
  ↓
ANOTHER TOOL
  ↓
LOGS
  ↓
REPORT
