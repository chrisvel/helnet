# helnet

```
dP                dP                     dP  v0.2
88                88                     88
88d888b. .d8888b. 88 88d888b. .d8888b. d8888P
88'  `88 88ooood8 88 88'  `88 88ooood8   88
88    88 88.  ... 88 88    88 88.  ...   88
dP    dP `88888P' dP dP    dP `88888P'   dP
```

`helnet` is a network scanner that finds vulnerable telnet servers that can be logged in with default credentials that mirai bot is using.

### Dependencies
- nmap
- net-telnet gem: https://github.com/ruby/net-telnet
- ipaddress gem

### How to run
`helnet` can scan networks with CIDR or single IP Addresses:

`./helnet.rb 192.168.0.0/16` or `./helnet.rb 192.168.1.2`

### License

Copyright (c) 2017 Chris Veleris

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
