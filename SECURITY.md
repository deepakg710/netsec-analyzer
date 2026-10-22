# Security Policy — NetSec Analyzer

## Safe Upload Handling and Privacy

NetSec Analyzer is designed local-first for sensitive network engineering environments:
1. **Zero External Data Transmission:** Configurations, topology graphs, and audit reports are processed and stored 100% locally on your machine. No telemetry or configurations are uploaded to cloud servers or external AI APIs.
2. **Untrusted Upload Sanitization:**
   - Strict 10MB per-file upload limit.
   - Uploads are saved with server-generated UUID file paths outside the public frontend root.
   - No execution of uploaded files (no subprocess execution, no shell command construction).
   - Safe path validation preventing directory traversal attacks (`../`).
3. **Safe Project Deletion:**
   - Deleting a project removes associated database records and uploads safely.
4. **Reporting Security Vulnerabilities:**
   - If you discover a vulnerability in NetSec Analyzer, please report it via private disclosure.
