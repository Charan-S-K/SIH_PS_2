# SecureMailScope Antigravity Prompt Pack

This pack is designed for a strict human-gated development workflow.

## Files

- `ANTIGRAVITY/MASTER_INSTRUCTION.txt` — give this to Antigravity as the single initial instruction.
- `ANTIGRAVITY/01_Implementation_Prompts.txt` — stage implementation prompts.
- `ANTIGRAVITY/02_Check_Prompts.txt` — stage verification prompts.
- `ANTIGRAVITY/03_Stage_Check_Report.txt` — local verification record; do not commit/push.
- `ANTIGRAVITY/PROJECT_STATE.md` — local development state; do not commit unless explicitly requested.
- `.gitignore` — excludes local verification/state files.

## Required workflow

1. Antigravity reads the prompt files.
2. Implement one stage.
3. Antigravity stops.
4. User confirms the stage should be checked.
5. Antigravity runs the check prompt.
6. Antigravity stops.
7. If issues exist, user decides whether to fix.
8. Fix and re-check until acceptable.
9. User explicitly approves Git action.
10. User manually commits/pushes/merges.
11. User tells Antigravity to continue.
12. Only then does Antigravity begin the next stage.

Antigravity must never autonomously push, merge, or continue through stages.
