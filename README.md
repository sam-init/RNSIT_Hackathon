# ph | GitHub-Native AI PR Review Copilot

## Problem
AI is speeding up software delivery, but it is also increasing review risk.

- GitHub reported that developers created more than **70,000 new public and open source generative AI projects in 2024**, with **98% year-over-year growth** in total generative AI projects.
- Stack Overflow's 2025 Developer Survey found that **84% of developers are using or planning to use AI tools**, yet **46% distrust AI output more than they trust it**.
- The same survey found **66% of developers are frustrated by AI code that is "almost right, but not quite."**
- GitHub also detected **more than 39 million secret leaks in 2024**.

The result: teams are shipping faster, but human reviewers are now overloaded with larger diffs, AI-assisted code, hidden security regressions, and inconsistent project structure.

## Why This Matters Now
Code review is no longer just about style or syntax.

Today, teams need to answer four questions before every merge:

1. Is this code safe?
2. Is it correct?
3. Is it scalable?
4. Does it fit the architecture of the repo?

`ph` solves that gap by acting like an always-on PR review squad inside GitHub, delivering inline, actionable comments within seconds of a pull request opening.

## Solution Overview
`ph` is a multi-agent PR review system that listens to GitHub webhooks, analyzes pull request diffs, and posts review comments directly on the changed lines.

It combines:

- a webhook-driven FastAPI backend
- a pattern-based security scanner
- an AI code review engine for correctness and maintainability
- a performance reviewer
- a structure reviewer for repo hygiene and architecture
- a validation layer that ensures every comment maps to a real line in the PR diff

## Architecture
```mermaid
flowchart LR
    A[GitHub Pull Request Event] --> B[/webhook FastAPI service]
    B --> C[HMAC verification]
    C --> D[Diff fetch + parsing]
    D --> E[Security scan]
    D --> F[AI code review]
    D --> G[Performance review]
    B --> H[Structure review]
    E --> I[Merge + dedupe + line validation]
    F --> I
    G --> I
    H --> J[GitHub PR review comments]
    I --> J
```

Architecture in plain English:

1. GitHub sends a PR webhook.
2. `ph` verifies the signature and fetches the diff.
3. The diff is analyzed by multiple reviewers in parallel.
4. Findings are merged, validated against real changed lines, and posted as native inline GitHub comments.
5. A separate structure reviewer evaluates the repository layout and architecture fit.

## Tech Stack
| Tool | Why it was used |
|---|---|
| FastAPI | Lightweight, fast webhook API with clear async lifecycle support |
| httpx + requests | Reliable outbound calls to GitHub and LLM endpoints |
| GitHub Pull Request Review API | Lets the product write inline comments where developers already work |
| OpenAI-compatible LLM interface | Keeps the system model-agnostic and easy to swap across providers |
| Regex security scanner | Gives instant deterministic findings before the LLM even responds |
| ThreadPoolExecutor | Runs review jobs without blocking webhook response time |
| Static HTML landing page | Makes the submission easy to demo visually without extra frontend build steps |
| Flask demo victim app | Provides an intentionally vulnerable PR target for a high-impact live demo |

## Key Features
- **Inline merge-blocking insight**: comments land exactly on risky lines, not in a detached dashboard.
- **Multi-angle review**: security, quality, performance, and architecture are checked in one pass.
- **GitHub-native workflow**: no context switching for developers or judges.
- **Fast first feedback**: PR authors get an acknowledgement instantly and actionable review comments shortly after.
- **Safer AI usage**: deterministic pre-scans and line validation reduce hallucinated or unusable feedback.
- **Demo-ready security narrative**: the repo includes a vulnerable sample app that makes the value obvious in seconds.

## Demo Flow
Use this exact flow for judges:

1. Open the landing page in [index.html](/d:/Apps/VS code/DevTools/RNSIT_Hackathon/index.html).
2. Explain the pain in one sentence: "AI helped developers write code faster, but reviewers still have to catch security and architecture issues before merge."
3. Show the webhook entrypoint in [main.py](/d:/Apps/VS code/DevTools/RNSIT_Hackathon/main.py).
4. Show the multi-agent reviewers in [ai_agent.py](/d:/Apps/VS code/DevTools/RNSIT_Hackathon/ai_agent.py) and [structure_agent.py](/d:/Apps/VS code/DevTools/RNSIT_Hackathon/structure_agent.py).
5. Use the intentionally vulnerable sample in [demo/vulnerable_library_app.py](/d:/Apps/VS code/DevTools/RNSIT_Hackathon/demo/vulnerable_library_app.py) as the PR target.
6. Walk judges through the outcome: secret exposure, injection risk, unsafe architecture, and poor performance are surfaced as GitHub-native inline comments.
7. Close with the product thesis: "`ph` reduces review latency while increasing trust in AI-assisted shipping."

## Repository Layout
```text
.
|- main.py                      # FastAPI webhook receiver
|- ai_agent.py                  # Core AI review engine
|- performance_agent.py         # Performance-focused reviewer
|- structure_agent.py           # Repository structure reviewer
|- index.html                   # Demo landing page
|- .env.example                 # Setup template
|- requirements.txt             # Python dependencies
`- demo/
   |- vulnerable_library_app.py # Intentional demo target for reviews
   `- README.md                 # How to use the sample during demos
```

## Quick Start
```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Then configure these secrets:

- `GITHUB_TOKEN`
- `WEBHOOK_SECRET`
- `LLM_API_KEY`
- optional: `PH_LLM_ENDPOINT`, `PH_LLM_MODEL`, `PH_WEBHOOK_WORKERS`

An example template is included in [.env.example](/d:/Apps/VS code/DevTools/RNSIT_Hackathon/.env.example).

## Future Scope
This is already shaped like a product, not just a prototype.

Next expansions that can turn `ph` into a startup-grade platform:

- org-wide review analytics and risk dashboards
- merge-gating policies based on severity thresholds
- auto-fix suggestions with one-click patch generation
- support for Jira, Slack, and CI/CD alerts
- learning from accepted vs dismissed comments to improve precision over time
- private deployment for regulated teams handling sensitive codebases

## What Makes This Hackathon-Ready
`ph` is easy to understand, easy to demo, and tied to a problem judges already believe is real:
teams are shipping faster with AI, but trust, security, and review quality are falling behind.

This project makes that tension visible and solves it where developers already work: inside the pull request.

## Sources
- GitHub Octoverse 2024: https://github.blog/news-insights/octoverse/octoverse-2024/
- Stack Overflow Developer Survey 2025 AI section: https://survey.stackoverflow.co/2025/ai
