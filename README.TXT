DNS Whitelist Daemon Version 1.0.0

1. Intro
Listens incoming DNS A queries. If query is for one of the domains in the whitelist,
an allow/pass firewall rule is added with the source and destination IP as the source
of the DNS query and the returned A record respectively. The firewall rule lives for
a certain period and automatically removed after reaching the time limit.

In a way, traffic between the source IP and the domain is allowed to pass through the
router/device.



2. Usage

The DNS Whitelist daemon is a component that is used with a captive portal to implement
a whitelist access channel. Users (based on their IP address) are allowed access to
a set of domains (websites) without any restrictions.



3. Compilation

$ tar xvf dnswld-XYZ.tgz
$ cd dnswld
$ make

Creates 'dnswld' binary executable.


4. Installation

Requires 'root' privilege.

$ make install

Installs 'dnswld' /usr/local/sbin and configuration file template to /etc/dnswld.cfg


5. Configuration

Default: /etc/dnswld.cfg

Use option '-c <config file>' to specify a different configuration file.


Directives:
-----------

1. whitelist - Space separated list of whitelist domains.

Example:
whitelist : www.facebook.com www.twitter.com www.cebu.com.ph


2. chains - Add allow iptable rules to the given chains.

Example:
chains: FORWARD


6. Running the daemon

$ ./dnswld

To see the options:
$ ./dnswld -h
./dnswld [Options]
Options:
 -d: Emit debug lines. Verbose
 -D: Foreground mode. Un-daemonize
 -c <config file>: Read config file. Default: /etc/dnswld.cfg
 -w <age>: Whitelist age in seconds. Default 300.
 -F: Disable adding firewall whitelist/allow rules.
 -h: Print this usage.


Example:
./dnswld -d -D -c ~sho/dnswld.cfg -w 120

- Enable debugging
- Run on foreground
- Use ~sho/dnswld.cfg config file
- Whitelist ACL/firewall rule age is 120 secs


