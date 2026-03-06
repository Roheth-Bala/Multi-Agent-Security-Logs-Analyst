# Multi-Agent Automated SOC Analyst (Extended)

A practical SOC automation project for incident triage using a multi-agent pipeline:

`IOC Extraction -> MITRE Mapping -> CVE Intelligence -> Investigation Plan -> Report`

This extended version includes:
- Modern responsive web UI with real-time progress
- Human-in-the-loop (HITL) validation before action execution
- Simulated in-memory response actions for users/cloud/terminals
- Optional MCP-routed external API mode for NVD and VirusTotal

---

## Credit

This project is inspired by and extended from work by **NathanCavalcanti**.

- Original inspiration/source by NathanCavalcanti
- This repository adds architecture, UX, and workflow extensions on top

If you publish this publicly, keep attribution visible in this section and in your repository description.

---

## Demo Video

Local demo recording:

- [Watch/Download Demo](docs/demo/demo.mp4)
- Direct path: `docs/demo/demo.mp4`

<video src="docs/demo/demo.mp4" controls autoplay muted loop playsinline width="100%"></video>

Note: Autoplay behavior depends on browser and GitHub rendering rules. If autoplay is blocked, use the play button.

Recommended demo flow:
1. Paste incident logs
2. Show live pipeline progress in UI
3. Show HITL validation panel
4. Approve selected actions
5. Show final report with validation and execution summary

---

## Key Features

### Core SOC Pipeline
- IOC extraction from unstructured incident text
- MITRE ATT&CK mapping
- CVE retrieval from NVD
- Investigation and containment plan generation
- Final structured JSON + text report

### Threat Intelligence Integrations
- NVD CVE search
- VirusTotal hash/IP/domain/URL enrichment

### UI and UX
- FastAPI + browser UI
- Real-time progress over WebSocket
- Live event log
- JSON + text report rendering

### Human-in-the-Loop (HITL)
- AI suggests involved parties and response actions
- Human review is required before action execution
- Explicit approve/reject decision
- Action execution is simulated in-memory (safe mode)

### Simulated Response Actions
- User actions: password reset, account disable
- Cloud actions: token/key revocation
- Terminal actions: isolation
- Updated simulated state is shown in final report

### Optional MCP Mode
- `direct` mode: API calls go directly to NVD/VirusTotal
- `mcp` mode: API calls are routed through an MCP bridge endpoint

---

## Architecture

### Agent Flow
1. `ioc_agent` extracts indicators
2. `mitre_agent` maps ATT&CK techniques
3. `cve_agent` retrieves likely CVEs
4. `investigation_agent` drafts response plan
5. `report_agent` generates final report
6. `hitl_agent` builds validation package (involved parties + proposed actions)
7. Human approves/rejects and selected actions are applied in simulated memory state

### Interfaces
- REST: `/analyze`, `/review/{session_id}`, `/review/{session_id}/decision`
- WebSocket: `/ws/analyze`
- UI: `/`

---

## Project Structure

```text
agents/
  ioc_agent.py
  mitre_agent.py
  cve_agent.py
  investigation_agent.py
  report_agent.py
  hitl_agent.py
  action_agent.py
app/
  api.py
  main.py
  config.py
  static/
    index.html
graph/
  graph_builder.py
  state.py
integrations/
  nvd_client.py
  virustotal_client.py
  mcp_transport.py
output/
```

---

## Requirements

- Python 3.12+
- Groq API key (required)
- Gemini API key (optional fallback)
- NVD API key (optional but recommended)
- VirusTotal API key (optional but recommended)

---

## Installation

```bash
git clone <your-repo-url>
cd Multi-Agent-Automated-SOC-Analyst-main
python -m venv .venv
```

### Windows

```bash
.venv\Scripts\activate
pip install -r requirements.txt
```

### Linux/Mac

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Environment Variables

Create `.env` in project root:

```env
# Required
GROQ_API_KEY=your_groq_key
GROQ_MODEL_DEFAULT=llama-3.1-8b-instant
GROQ_MODEL_ANALYSIS=llama-3.3-70b-versatile

# Optional fallback
GEMINI_API_KEY=your_gemini_key
GEMINI_MODEL=gemini-1.5-flash

# Threat intelligence (optional)
NVD_API_KEY=your_nvd_key
VIRUSTOTAL_API_KEY=your_virustotal_key

# External API transport mode
# direct = call NVD/VT directly
# mcp    = route through MCP bridge endpoint
SOC_EXTERNAL_API_MODE=direct
SOC_MCP_BRIDGE_URL=http://localhost:8080/mcp/http
```

---

## Run

### CLI Mode

```bash
python -m app.main
```

### API + UI Mode

```bash
uvicorn app.api:app --reload
```

Open:
- UI: `http://127.0.0.1:8000/`
- API docs: `http://127.0.0.1:8000/docs`

---

## Example Incident Inputs

```text
Suspicious PowerShell execution detected:
powershell -enc KABDA...
Source IP: 192.168.1.100
Target: malicious-domain.com
END
```

```text
Multiple failed logins followed by success:
username: alice.w
source_ip: 185.225.73.14
destination_host: fin-app-01
event: 18 failed RDP attempts, then successful login
process: cmd.exe /c whoami
END
```

```text
Suspicious AWS console activity:
cloud_account: prod-billing
iam_user: svc_backup
source_ip: 91.240.118.22
event: MFA disabled + access key created + S3 bucket policy changed to public
resource: s3://billing-exports
END
```

---

## HITL Workflow

1. User submits incident text
2. Agent pipeline completes
3. UI displays validation panel with:
   - Suggested involved parties
   - Proposed response actions
   - Simulated in-memory entities
4. Human approves/rejects and selects actions
5. Backend applies selected actions to in-memory state
6. Final report includes:
   - Human validation decision
   - Validated actions
   - Simulated environment state
   - Action execution outcomes

---

## API Quick Reference

### Health

`GET /health`

### Analyze (non-HITL direct result)

`POST /analyze`

```json
{
  "incident": "incident text..."
}
```

### Analyze with live updates + HITL

`WS /ws/analyze`

Receives events:
- `status`
- `step`
- `validation_required`
- `error`
- `done`

### Get pending review

`GET /review/{session_id}`

### Submit human decision

`POST /review/{session_id}/decision`

```json
{
  "decision": "approved",
  "reviewer": "analyst-1",
  "notes": "Looks valid",
  "overrides": {},
  "selected_action_ids": ["action-id-1", "action-id-2"]
}
```

---

## Security Notes

- Current action execution is simulation-only (in-memory), safe for demos/labs
- Do not treat generated content as final evidence without analyst validation
- Add authentication/authorization before deploying in shared or production environments
- Restrict CORS in production

---

## Suggested Next Improvements

- Persist review sessions in SQLite/Redis instead of memory
- Add role-based approval for high-risk actions
- Add SIEM/EDR connectors for real action execution behind policy gates
- Add unit/integration tests for HITL and action simulation flows
- Add structured telemetry and audit trails for all approval steps

---

## License

Use the original project license terms and preserve attribution to NathanCavalcanti.
"# Multi-Agent-Security-Logs-Analyst" 
