# Lab Scope

This document defines the boundaries of the defensive research environment.

## In Scope

- Systems owned or explicitly authorized for testing
- Local virtual machines
- Disposable snapshots
- Hypervisor configuration review
- Controlled guest operating systems
- High-level review of virtualization trust boundaries
- Logging, tracing, and behavior documentation

## Out of Scope

- Production systems
- Third-party infrastructure
- Unauthorized cloud workloads
- Public targets
- Credential access or persistence testing outside a lab
- Publishing exploit chains before coordinated disclosure

## Safety Controls

- Disable shared clipboard unless needed
- Disable shared folders unless needed
- Avoid bridged networking by default
- Disable USB passthrough unless needed
- Use snapshots before each test
- Keep test artifacts isolated
- Record configuration changes and assumptions
