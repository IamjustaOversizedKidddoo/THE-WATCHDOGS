<div align="center">

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

> [!IMPORTANT]
> **Third-Party Open-Source Attribution & Architecture**  
> The Watchdogs is an orchestration harness that coordinates several independent, third-party open-source security tools as specialized agent desks. **These tools are not authored by this project; The Watchdogs wraps and coordinates them under strict scope and approval rails.**  
> - **/jonathan** → [HackerGPT](https://github.com/stalane/HackerGPT) (GNU GPL-3.0)
> - **/chris** → [Strix](https://github.com/usestrix/strix) (Apache-2.0)
> - **/daniel** → [Shannon](https://github.com/KeygraphHQ/shannon) (GNU AGPL-3.0)
> - **/david** → [HackBot](https://github.com/morpheuslord/HackBot) (© Chiranjeevi G. / morpheuslord)
> - **/wrench** / **/gabriel** → [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) (MIT)
> - **/maverick** → [Skills Library](https://github.com/anthropics/anthropic-quickstarts) (Apache-2.0)
>
> All original upstream `.git` histories, authorship records, and `LICENSE` files are strictly preserved in each tool's directory. For full licensing details, links, and upstream asset credits, see [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).

---

# 🐺 What is THE WATCHDOGS?

**THE WATCHDOGS** is an experimental multi-agent cybersecurity platform exploring how autonomous security agents can work together as a coordinated security team — while their activity is represented through a **living pixel-art office**.

Instead of watching a collection of terminals and logs, the operator sees agents physically moving through an office, going to different workstations, performing tasks, communicating, waiting for decisions, and responding to real backend events.

The core idea:

> **The pixel office is not the cybersecurity system.**  
> **It is the visual interface to the cybersecurity system.**

---

# ⚡ The Concept

Traditional security automation often looks like:

```text
TARGET → TOOL → OUTPUT → ANOTHER TOOL → LOGS → REPORT
```

THE WATCHDOGS explores a coordinated multi-agent model:

```text
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
```

The objective is not simply to automate individual security tools. The objective is to explore a coordinated security workforce made up of specialized agents.

---

# 🏢 The Living Security Office

The defining feature of THE WATCHDOGS is its office visualization. Every agent has a workstation, physical location, movement between desks, task-specific animations, and approval states.

```text
DESK → RECON STATION → WORKING → MEETING / COMMUNICATION → VALIDATION → REPORTING
```

The office answers three questions immediately:
> *Who is working? What are they doing? Does anything require my attention?*

---

# 🧠 Real Backend Activity → Visual Behavior

The architecture connects the visual layer to real backend activity:

```text
REAL AGENT / PROCESS → AGENT STATE → EVENT → OFFICE STATE → CHARACTER MOVEMENT → ANIMATION
```

---

# 👥 Specialized Watchdogs Roster

The project is based around specialized agents rather than one AI attempting to perform every part of a security operation:

* **/michael** — Orchestrator & floor manager. Routes work, tracks budgets, enforces pacing, and handles human escalation.
* **/jonathan** — Reconnaissance & continuous attack surface mapping with delta diffing.
* **/daniel** — Code review, static analysis (SAST), and deep structural vulnerability inspection.
* **/chris** — Discovery validation & exploit PoC verification with strict pre-execution gating.
* **/david** — Automation, fast CVE lookups, Active Directory automation, and payload suggestions.
* **/rooster** — AI/Chatbot red teaming, prompt injection, and model security evaluation.
* **/maverick** — On-demand librarian curating 818 structured offensive security skills.
* **/wrench** (or **/gabriel**) — 150+ tool cybersecurity MCP server floor.

---

# 🐝 The Hive

At the center of THE WATCHDOGS is the **Hive**, providing asynchronous mailboxes, blackboards, shared state, and durable memory across desks.

```text
HIVE → [TASKS · MESSAGES · FINDINGS · MEMORY] → ORCHESTRATOR
```

---

# 🔐 Human-in-the-Loop & Authorization First

THE WATCHDOGS is designed around hard human oversight. Autonomous agents cannot execute intrusive or exploit actions without explicit permission.

```text
Agent proposes action → Authorization check → Scope check → Risk / policy check → Human approval → APPROVE / DENY
```

### Fail Closed Principle
When authorization, scope, or policy information is uncertain: **STOP**. The system does not assume authorization.

---

# 📂 Repository Layout

| Directory | Component | Source Project | License | Role |
| :--- | :--- | :--- | :--- | :--- |
| [`munder-difflin/`](./munder-difflin) | **App & Orchestrator** | Munder Difflin | MIT License | Living office UI, PTY layer, router, approval queue |
| [`jonathan/`](./jonathan) | **/jonathan** | HackerGPT | GNU GPL-3.0 | Continuous recon desk (Git Submodule) |
| [`chris/`](./chris) | **/chris** | Strix | Apache-2.0 | Exploitation validation desk (Git Submodule) |
| [`daniel/`](./daniel) | **/daniel** | Shannon | GNU AGPL-3.0 | SAST & code review desk (Git Submodule) |
| [`david/`](./david) | **/david** | HackBot | Public Repo (© author) | Automation & CVE lookup desk (Git Submodule) |
| [`wrench/`](./wrench) | **/wrench** | HexStrike AI | MIT License | 150+ tool MCP floor (Git Submodule) |
| [`skills-library/`](./skills-library) | **/maverick** | Skills Library | Apache-2.0 | 818 practitioner skills (Git Submodule) |
| [`workLogs/`](./workLogs) | **Persistence** | — | — | Hive audit logs, blackboard, and session states |

See [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) for complete attribution and license terms.
