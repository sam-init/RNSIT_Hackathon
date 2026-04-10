# Demo Assets

This folder contains the intentionally vulnerable sample application used to demo `ph`.

Why it exists:

- it gives judges a concrete "before review / after review" story
- it makes security findings visually obvious in under 10 seconds
- it shows that `ph` is not just a chatbot, but a pull-request-native reviewer

Primary file:

- [vulnerable_library_app.py](/d:/Apps/VS code/DevTools/RNSIT_Hackathon/demo/vulnerable_library_app.py)

Suggested demo setup:

1. Open a PR that introduces or modifies vulnerabilities in the sample app.
2. Trigger the GitHub webhook.
3. Show how `ph` posts inline comments on the risky lines.

If you want to run the sample locally, install the demo dependency with:

```bash
pip install -r demo/requirements.txt
python demo/vulnerable_library_app.py
```
