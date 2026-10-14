# Egyxos Advanced Web Security Scanner Architecture

## Overview

Egyxos Advanced Web Security Scanner is designed as a modular security-assessment platform with explicit safety boundaries. The system keeps a human in the loop and separates project, scope, tool execution, and evidence into distinct architectural layers.

## Components

- CLI layer: command parsing and interactive shell experience
- Project layer: project creation, storage, and default configuration
- Scope layer: validation and approved target enforcement
- Session layer: stateful assessment tracking
- Agent layer: objective planning and approval management
- Tool layer: registry and adapters for external security tools
- Findings layer: structured vulnerability records and evidence handling
- Reporting layer: Markdown, HTML, and JSON outputs
- Doctor layer: validation of the environment and installed dependencies

## Security model

The platform explicitly enforces least privilege, scope checks, and approval gates before dangerous actions occur. It stores evidence without exposing credentials and keeps logs aligned with operational intent.
