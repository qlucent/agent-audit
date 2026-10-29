# Security policy

Please report vulnerabilities privately through [GitHub security advisories](https://github.com/qlucent/agent-audit/security/advisories/new) rather than in public issues.

Anything that makes the CLI or library send data off the machine, or print a secret or a free-text field from a spec unmasked, is in scope and treated as high severity, because this tool promises that nothing leaves your machine and that secrets are masked in every output.

A wrong classification or a missed finding is not a vulnerability. Report it as a [false positive or new rule](https://github.com/qlucent/agent-audit/issues/new/choose).
