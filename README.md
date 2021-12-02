dns-network-access-controller
=============================

Listens incoming DNS A queries. If query is for one of the domains in the whitelist, an allow/pass firewall rule is added with the source and destination IP as the source of the DNS query and the returned A record respectively. The firewall rule lives for a certain period and automatically removed after reaching the time limit.  In a way, traffic between the source IP and the domain is allowed to pass through the router/device.

## Donation
If this project help you reduce time to develop, you can give me a bottle of beer or buy me a shot of whiskey :)

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/donate?hosted_button_id=BXK736WX48DVL)
