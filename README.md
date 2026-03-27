# did:webvh Java Library

[![CI](https://github.com/european-epc-competence-center/didwebvh/actions/workflows/ci.yml/badge.svg)](https://github.com/european-epc-competence-center/didwebvh/actions/workflows/ci.yml)

A Java library implementing the [`did:webvh`](https://identity.foundation/didwebvh/v1.0/) DID method (DID Web + Verifiable History). `did:webvh` enhances `did:web` with a cryptographically verifiable, tamper-evident history, self-certifying identifiers (SCIDs), and optional features such as key pre-rotation, witnesses, and DID portability — without relying on a ledger.

## Repository Overview

```
/
├── .github/workflows/ # CI: tests on push to `main` (`ci.yml`)
├── didwebvh-java/     # Java library (Maven, Java 21) — main implementation
├── spec/              # did:webvh specification v1.0 source files
├── docs/              # Thesis documentation
├── README.md
└── CHANGELOG.md
```

## Specification

This library targets `did:webvh` **v1.0**:
- Spec: https://identity.foundation/didwebvh/v1.0/
- Info site: https://didwebvh.info/latest/

## Local Development

**Requirements:** Java 21 JDK, Maven 3.9+

```bash
# Build
cd didwebvh-java
mvn compile

# Run tests
mvn test

# Package as JAR
mvn package
```

The library is not yet published to Maven Central. To use it locally:
```bash
mvn install   # installs to local ~/.m2 repository
```

Then add to your project:
```xml
<dependency>
  <groupId>io.didwebvh</groupId>
  <artifactId>didwebvh-java</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Usage

> Implementation in progress — API not yet functional.
