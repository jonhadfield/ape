
# ape: AWS account scanner
[![CircleCI](https://circleci.com/gh/jonhadfield/ape/tree/master.svg?style=shield&circle-token=16e5cf0096cd4f6c7894e10f25b51e07746fa0b7)](https://circleci.com/gh/jonhadfield/ape/tree/master) [![Go Report Card](https://goreportcard.com/badge/github.com/jonhadfield/ape)](https://goreportcard.com/report/github.com/jonhadfield/ape)

- [about](#about)
- [quickstart](#quickstart)
- [concept](#concept)

## about

ape is a tool for scanning AWS accounts to discover issues such as security vulnerabilities.
It's fast, and it's written in Go, so there are no dependencies to install.

## compatibility

Only tested on Linux and MacOS.

## quickstart

### docker
The following will run the [AWS CIS Foundations](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf) preset against a single account.  

```bash
$ docker run --rm -t quay.io/jonhadfield/ape \
             --run-preset=cis-foundations \
             --access-key-id=ACCESS-KEY-ID \
             --secret-access-key=SECRET-ACCESS-KEY   
```
Replace 'ACCESS-KEY-ID' and 'SECRET-ACCESS-KEY' with your credentials.
To create a user with the minimum permissions required to run this preset, see [here](https://github.com/jonhadfield/ape/blob/master/docs/cis-foundations-policy.md). 

### install and run

Download the latest release here: https://github.com/jonhadfield/ape/releases and install:

``
$ install <ape binary> /usr/local/bin/ape
``

To run the built-in [AWS CIS Foundations](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf) preset, [set your AWS credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html) and then run:

``
$ ape --run-preset=cis-foundations
``

## concept

### the basics

ape runs **playbook** files containing a list of tasks called **plays**. Each **play** defines one or more **policies** to run, and it's the policies that tell ape how to find issues through the use of **filters**.
All of these are defined using a simple markup language called [YAML](http://yaml.org/).

#### playbook

A playbook file, in its simplest form, is a list of plays. By default, each play will be executed in turn against the account matching the credentials ape is called with. 
Other configuration items, including email and Slack reporting integrations are also defined here. 

#### play

A play lists the policies to run and also lets you define which **targets** (AWS accounts) and regions to run them against. 

#### policy

A policy defines the AWS **resource** type and one or more **filters** to run against items of that type.
	
#### filter

A filter consists of one or more resource **criterion** (instance attribute) and value to match on.
