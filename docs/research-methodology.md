# Research Methodology

The purpose of this methodology is to support safe and repeatable defensive vulnerability research.

## 1. Define the Question

Start with a narrow research question, such as:

- What trust boundary is being reviewed?
- What component owns the privileged operation?
- What behavior would be unexpected or security-relevant?
- Is the test about configuration, isolation, emulation, memory mapping, or device exposure?

## 2. Build a Controlled Test Case

Tests should answer one question at a time. The environment should be reproducible and isolated from production systems.

## 3. Observe Behavior

Use non-invasive observation first:

- System logs
- Hypervisor logs
- Configuration diffs
- Process and file activity
- Network behavior in isolated mode
- Version and feature flags

## 4. Document Findings

A useful note should include:

- Environment details
- Hypervisor version
- Host OS version
- Guest OS version
- CPU virtualization feature set
- Configuration
- Steps taken at a high level
- Expected behavior
- Observed behavior
- Security impact hypothesis
- Whether the issue is reproducible

## 5. Validate Responsibly

If a potential vulnerability is found, avoid publishing exploit details. Prepare a concise report for the vendor or authorized program.
