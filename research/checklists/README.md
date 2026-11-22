# Audit checklists

These checklists document how each area of a WordPress site is assessed: what to look at, why it
matters, and how to fix it. They were written as working notes, partly in French, partly in English.

**Read this before using them.** Some sections describe *manual* tests that go beyond what the tool
does: file uploads, login attempts, comment submissions, crafted requests. Those are active intrusion
tests. They change the state of the target or try to break its controls, and they are lawful only
with the site owner's written authorisation, inside a penetration test engagement.

wp_security_ForSure itself never performs them: it only sends read requests (`GET`, `HEAD`,
`OPTIONS`). See [`docs/RESPONSIBLE_USE.md`](../../docs/RESPONSIBLE_USE.md).

Start with `00-checklist-maitre-workflow.md`. The legal framework is in `19-legal-ethics.md`.
