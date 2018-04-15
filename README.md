
# ape: security scanner for AWS
[![CircleCI](https://circleci.com/gh/jonhadfield/ape/tree/master.svg?style=shield&circle-token=16e5cf0096cd4f6c7894e10f25b51e07746fa0b7)](https://circleci.com/gh/jonhadfield/ape/tree/master)

- [about](#about)
- [quickstart](#quickstart)
- [concept](#concept)

## about

ape enables you to scan your AWS accounts from the command-line.
It's fast, and it's written in Go, so there are no dependencies.
You can run the run the built-in presets (just [AWS CIS Foundations](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf) for now) or define your own with YAML files.

## compatibility

Only tested on Linux and MacOS.

## quickstart

download the latest release here: https://github.com/jonhadfield/ape/releases and install:

```bash
$ install <ape binary> /usr/local/bin/ape
```

create an IAM user (or an IAM role to assume) with the minimum permissions required to run the CIS foundations checks found [here](docs/cis-foundations-policy.md).

run the CIS Foundations preset:

```bash
$ ape --run-preset cis-foundations
```

## concept

### the basics

ape runs playbooks. A playbook is a YAML file specifying which policies to run. For example:

```yaml
---
 plays:
   - name: "CIS 1.13"
     policies:
       - "ensure MFA is enabled for the root account"
   - name: "CIS 1.14"
     policies:
       - "ensure hardware MFA is enabled for the root account"
```

Policies are also defined in YAML files, and define filters used to find matching resources. For example:

```yaml
---
policies:
  - name: "ensure MFA is enabled for the root account"
    resource: iam:User
    filters:
      - criterion: UserName
        comparison: "in"
        values:
          - "root"
      - criterion: HasMFADevice
        value: "false"

  - name: "ensure hardware MFA is enabled for the root account"
    resource: iam:User
    filters:
      - criterion: UserName
        comparison: "in"
        values:
          - "root"
      - criterion: HasHardwareMFADevice
        value: "false"
```

