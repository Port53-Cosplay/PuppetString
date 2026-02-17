Review all recently changed files for security issues. Check for:

1. Shell injection (subprocess with shell=True, unsanitized inputs to commands)
2. Path traversal (unvalidated file paths, missing .resolve() checks)
3. Hardcoded secrets or API keys
4. Unsafe YAML loading (yaml.load without safe Loader)
5. eval/exec usage on untrusted data
6. SQL injection (string concatenation in queries)
7. Bare except blocks that swallow errors silently
8. Sensitive data in log output
9. Missing input validation on CLI args or config values
10. Pickle deserialization of untrusted data
11. OWASP Top 10 web vulnerabilities if applicable (XSS, SSRF, etc.)

For each issue found, explain the risk and provide the fix. If no issues are found, confirm the code is clean.
