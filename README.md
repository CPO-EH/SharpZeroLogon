# SharpZeroLogon

Zerologon Exploiter I used used while Red Teaming, within Cobalt Strike -> Execute-Assembly

Heavily based on -> https://github.com/CPO-EH/CVE-2020-1472_ZeroLogonChecker

This version can:

- Check for DC Vulnerability

- Exploit vulnerable DC

- List local DCs

Command line:

- SharpZeroLogon.exe <target dc fqdn> <optional: -reset> <optional: -listdc>
