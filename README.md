# network-vuln-feed

## Purpose
Security advisories published by various network equipment vendors are not machine-readable, or even if they are in a format such as CVRF/CSAF, the descriptions of affected products are unstable, making it difficult to effectively use them.  
This repository rewrites these security advisories in a machine-processable format, organizes the affected products, and distributes them in a form that can be used by vulnerability scanners.  
And implement tools to assist in the creation of those advisories.

## Usage
```console
$ go build -a -o network-vuln-feed ./cmd

$ network-vuln-feed help
network-vuln-feed: discover and collect security advisories for network devices

Usage:
  network-vuln-feed [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  discover    discover new and updated advisories
  help        Help about any command
  template    create a template for a Vuls format advisory

Flags:
  -h, --help   help for network-vuln-feed

Use "network-vuln-feed [command] --help" for more information about a command.
```