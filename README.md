# RedTeam MCP

Personal red-team automation lab: recon → vuln scan → exploit research →
reporting, usable either as a standalone Ollama-driven CLI tool
(`ai_controller.py`) or as a real MCP server (`orchestrator.py`) that
Claude Desktop (or any other MCP client) can drive directly.

## Scope — read this before running anything

**This tool only operates against devices explicitly listed in
`config/allowlist.json`.** That file is intentionally NOT committed to
git (see `.gitignore`) — every fresh clone, VM, or new install must
create its own copy and fill in devices that installation's operator
actually owns and is authorized to test.

There is no supported way to disable this check, and no default
allowlist ships with the code — the project will refuse to even
import if `config/allowlist.json` doesn't exist. This is deliberate.

If you're setting this up for yourself on a new machine, or handing it
to someone else: **the very first thing to do is create and correctly
fill in your own `config/allowlist.json`.** Do this before installing
anything else.

No client work without a signed scope of work. Personal lab devices
only.

---

## Architecture

```
ai-redteam/
├── config/
│   ├── allowlist.example.json   # template, safe to commit
│   └── allowlist.json           # YOUR real scope — gitignored, create this yourself
├── tools/
│   ├── allowlist.py             # scope enforcement + safe subprocess helper (everything else depends on this)
│   ├── recon.py                 # nmap, dig, whois, banner grab, http headers
│   ├── vuln_scan.py             # nikto, nmap NSE vuln scripts, security header check
│   ├── exploit.py               # searchsploit/msf_search (read-only lookups) + reverse shell TEXT generator
│   └── reporting.py             # SQLite-backed finding log + Markdown report generator
├── ai_controller.py             # standalone Ollama-driven CLI controller (no MCP)
├── orchestrator.py              # the real MCP server (FastMCP), for Claude Desktop / any MCP client
├── reports/                     # generated findings.db + markdown reports — gitignored, personal data
└── venv/                        # Python virtualenv — gitignored, recreate per machine
```

Every tool function in `recon.py`/`vuln_scan.py`/`exploit.py`/`reporting.py`
independently re-validates its target against `tools/allowlist.py` before
doing anything — this isn't just enforced at the controller/orchestrator
layer, so there's no single bypass point.

---

## Fresh setup (new machine, new VM, or a friend's own install)

### 1. Clone and set scope FIRST

```bash
git clone https://github.com/AquaInferno/RedTeamAI ai-redteam
cd ai-redteam
cp config/allowlist.example.json config/allowlist.json
```

Edit `config/allowlist.json` — replace the placeholder IPs with devices
YOU own:

```json
[
  {"ip": "192.0.2.10", "label": "My Phone"},
  {"ip": "192.0.2.11", "label": "My Desktop"},
  {"ip": "192.0.2.12", "label": "My Laptop"}
]
```

### 2. Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install "mcp[cli]" requests
```

Verify the scope config loads correctly:

```bash
python3 -c "from tools.allowlist import ALLOWLIST; print(ALLOWLIST)"
```

If this errors with `ScopeConfigError`, go back to step 1 — you skipped
creating `config/allowlist.json`.

Add a convenience alias so you don't have to remember the venv path
every new terminal (Kali defaults to zsh):

```bash
echo "alias redteam-env='source ~/ai-redteam/venv/bin/activate && cd ~/ai-redteam'" >> ~/.zshrc
source ~/.zshrc
```

New terminals: just type `redteam-env` to jump in ready to go.

### 3. Commit immediately

This project has been lost to a full OS wipe once already. Don't wait
until it's "done" to start tracking it:

```bash
git config --global user.email "you@example.com"   # any consistent value works, doesn't need to be real
git config --global user.name "Your Name"
git add .
git commit -m "initial setup"
git push
```

---

## Running standalone (Ollama controller, no MCP)

Needs a tool-calling-capable Ollama model. Vanilla `llama3.1:8b` works
out of the box:

```bash
ollama pull llama3.1:8b
ollama serve          # or check `systemctl status ollama` — install.sh sets this up as a service on Linux
```

In another terminal:

```bash
redteam-env
python3 ai_controller.py
```

Type prompts at the `you>` prompt. Recon/vuln-scan/reporting tools run
automatically; anything in `exploit.py` (`searchsploit_query`,
`msf_search`, `generate_reverse_shell`) prompts you for `y/n`
confirmation in the terminal before running, regardless of what the
model requests.

**Do not run `python3 orchestrator.py` the same way** — see next
section, different transport entirely.

---

## Running as an MCP server (orchestrator.py)

`orchestrator.py` uses stdio/JSON-RPC transport. Running it directly in
a terminal and typing at it will just look hung — it's waiting for a
real MCP client, not keyboard input.

**Standalone test** (MCP Inspector web UI):
```bash
redteam-env
mcp dev orchestrator.py
```

**Quick scripted test** (no UI, exercises the real `mcp.call_tool` path):
```bash
python3 -c "
import asyncio
from orchestrator import mcp

async def main():
    tools = await mcp.list_tools()
    print(f'{len(tools)} tools registered')
    result = await mcp.call_tool('list_findings', {})
    print(result)

asyncio.run(main())
"
```

### Trust model — important

Unlike `ai_controller.py`, `orchestrator.py` has **no input()-based
confirmation gate** for exploit tools — stdio has no terminal to prompt
against. The human checkpoint for `searchsploit_query`, `msf_search`,
and `generate_reverse_shell` is **whatever MCP client you connect this
to** (e.g. Claude Desktop's own per-call "Allow this tool?" approval
UI). Before trusting this with anything exploit-related, confirm your
specific client actually prompts per-call rather than auto-approving.

---

## Installing into Claude Desktop (Desktop Extension / .mcpb)

Claude Desktop no longer uses a hand-edited `claude_desktop_config.json`
for this — it uses packaged `.mcpb` extension bundles installed through
Settings → Extensions → Advanced settings → Extension Developer →
Install Extension...

### Build the bundle

Needs Node/npm (separate from the Python venv):
```bash
sudo apt install -y nodejs npm
sudo npm install -g @anthropic-ai/mcpb
```

```bash
mkdir ~/ai-redteam-mcpb
cd ~/ai-redteam-mcpb
mcpb init
```

The wizard will generate a `manifest.json` — **it will get several
things wrong that need manual correction**:

1. `mcp_config.command` — the wizard defaults to a bare `python`. This
   must be the FULL path to your venv's Python, e.g.
   `/home/youruser/ai-redteam/venv/bin/python3` — Claude Desktop
   launches extensions with a minimal PATH that won't have your venv
   active, so a bare `python`/`python3` hits the system interpreter,
   which doesn't have `mcp` installed.
2. `mcp_config.args` — since `orchestrator.py` lives outside this
   bundle folder, this must be the plain absolute path to it (e.g.
   `/home/youruser/ai-redteam/orchestrator.py`), NOT prefixed with
   `${__dirname}` — the wizard sometimes concatenates both, producing
   a broken nonsense path.
3. `env.PYTHONPATH` pointing at `${__dirname}/server/lib` — this is a
   template default for bundles that vendor their own dependencies.
   We don't do that (dependencies live in the venv) — remove this key
   entirely.
4. `tools` array — fill in the real tool list from `orchestrator.py`
   rather than leaving only whatever placeholder you typed to get
   through the wizard. Regenerate anytime with:
   ```bash
   python3 -c "
   import asyncio
   from orchestrator import mcp
   async def main():
       for t in (await mcp.list_tools()):
           print(f'    {{\"name\": \"{t.name}\", \"description\": \"{(t.description or \"\").splitlines()[0]}\"}},')
   asyncio.run(main())
   "
   ```

Then:
```bash
mcpb validate manifest.json
mcpb pack . redteam-mcp.mcpb
```

Install via Settings → Extensions → Advanced settings → Extension
Developer → Install Extension..., pointing at the generated `.mcpb`
file.

**This bundle is NOT portable between machines/users** — it has
absolute paths baked in (your home directory, your venv location). A
new machine, VM, or a friend's install needs to run through this whole
`mcpb init`/`pack` process fresh with their own paths. This is also why
built `.mcpb` files and `manifest.json` (once it has real paths in it)
are gitignored rather than committed.

---

## Hardware/driver notes (NVIDIA + Ollama)

If Ollama's log shows it loading models on `Vulkan0` instead of `CUDA`
despite having an NVIDIA card, the proprietary driver likely isn't
installed (Kali ships `nouveau` by default). Fix:

```bash
sudo apt update && sudo apt full-upgrade -y
sudo reboot                                          # if a new kernel was pulled in
sudo apt install -y linux-headers-$(uname -r)
sudo apt install -y nvidia-driver
sudo reboot
nvidia-smi                                           # should show your GPU + driver + CUDA version
```

Before touching drivers on a system you care about, snapshot first:
```bash
sudo apt install -y timeshift
sudo timeshift --create --comments "pre-nvidia-driver" --tags D
```
and check secure boot state (`mokutil --sb-state`) — if enabled, the
driver install will require an extra MOK enrollment step on next boot
that's easy to get wrong.

---

## Known accuracy caveat — local LLM hallucination

An 8B local model (llama3.1:8b) doing tool-calling has, in testing,
both invented findings not present in tool output and paraphrased raw
service names into more "familiar-sounding" but incorrect ones (e.g.
nmap's literal `msrpc` service name reported as `Microsoft-DS`, which
is a different, unrelated service). `ai_controller.py`'s system prompt
has explicit anti-hallucination instructions to mitigate this, but
**always cross-check a model's summary against the raw `stdout` in the
actual tool result** before trusting or logging a finding — treat the
tool result as ground truth and the model's prose as an unverified
summary, especially with a small local model.

---

## Legal

Personal lab use only. Every device in `config/allowlist.json` must be
one you own and are authorized to test. Not to be used against anything
outside that list. No client work without a signed scope of work.
