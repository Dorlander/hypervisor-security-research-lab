# Hypervisor Lab Checklist

Use this checklist before running a controlled virtualization security test.

## Host Preparation

- Confirm the host system is not used for production work
- Apply current OS security updates
- Record CPU model and virtualization feature support
- Record hypervisor name and version
- Create a clean workspace for notes and logs

## Guest Preparation

- Use a disposable guest VM
- Create a snapshot before testing
- Disable shared clipboard
- Disable shared folders
- Disable drag-and-drop
- Disable USB passthrough
- Prefer NAT or host-only networking
- Avoid bridged networking unless necessary

## Test Documentation

Record:

- Date
- Host OS
- Guest OS
- Hypervisor version
- Relevant CPU virtualization features
- VM configuration
- Expected behavior
- Observed behavior
- Logs collected
- Reproduction reliability

## After Testing

- Revert snapshots if needed
- Archive notes safely
- Remove temporary artifacts
- Decide whether the result is expected behavior, a hardening note, or a potential vulnerability
