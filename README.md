# dns_dump

Get the available DNS records for a given host. Removes duplicate SOA records that are received for requested records which are
not implemented by the host. Various options are available:

-A    Do an AXFR zone transfer request (under construction)
-S    Specify to which DNS resolver dns_dump should send the request(s)
-p    Specify the port number to use (default is 53)
-N    Write results to stdout instead of to a file (default is to output to a file)
-c    If outputting to a file, do not automatically open the file when done
-E    Choose which text editor to use to open results file (default is to just exec xdg-open)
-v    Verbose - output more messages while running
-d    Debug mode - output diagnostic messages while running
-q    Quiet mode - diverts stdout and stderr to /dev/null
-h    Displays informational menu

Example:

```
./dns_dump example.com -S 8.8.8.8 -E "gedit" -q
```

This would run dns_dump in quiet mode, send queries to google's DNS server, and open the results file with gedit
