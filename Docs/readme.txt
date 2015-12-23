ProxHTTPSProxyMII
=================

Created to provide modern nag-free HTTPS connections for an HTTP proxy.

How it works
----

![how it works](http://www.proxfilter.net/proxhttpsproxy/HowItWorks.gif)

Eligible HTTP Proxies
----

* The [Proxomitron](http://www.proxomitron.info), for which ProxHTTPSProxy was created :)
* Any that have the ability to forward all requests with a "Tagged:ProxHTTPSProxyMII FrontProxy/*" header to the ProxHTTPSProxyMII rear server.
* Any that can be ran as two instances, one for true http and another for "tagged" http
* Any that will only be used to monitor https traffic  

Install
----

* ProxHTTPSProxy's "CA.crt" to the Client's store of trusted certificate authorities.

Configure
----

* The Client to use the ProxHTTPSProxy front server at 127.0.0.1 on port 8079 for secure connections.
* The HTTP proxy to receive requests at 127.0.0.1 on port 8080.
* The HTTP proxy to forward requests to the ProxHTTPSProxy rear server at 127.0.0.1 on port 8081.
* Edit "Config.ini" to change these requirements.

Execute
----

ProxHTTPSProxy.exe to start.

Remember
----

Be aware and careful! Use a direct connection when you don't want any mistakes made.

Use at your own risk!

Have fun!

Discuss
----

<http://prxbx.com/forums/showthread.php?tid=2172>

Author
----

* phoenix (aka whenever)
* JJoe (test and doc)

Proxomitron Tips
================

To use
----

* Add the ProxHTTPSProxy rear server to the Proxomitron's list of external proxies

  `127.0.0.1:8081 ProxHTTPSProxyMII`

* Add to Proxomitron's "Bypass URLs that match this expression" field if it is empty

  `$OHDR(Tagged:ProxHTTPSProxyMII FrontProxy/*)$SETPROXY(127.0.0.1:8081)(^)`

* Add to the beginning of the entry in Proxomitron's "Bypass URLs that match this expression" field if it is **not** empty

  `$OHDR(Tagged:ProxHTTPSProxyMII FrontProxy/*)$SETPROXY(127.0.0.1:8081)(^)|` 

Tips
----

* Proxomitron always executes some commands in "Bypass URLs that match this expression" field. Adding the entry there allows the Proxomitron to use the rear server when in Bypass mode.

  This undocumented feature brings many possibilities but remember, an actual match triggers bypass of filtering!
  
  - `$OHDR(Tagged:ProxHTTPSProxyMII FrontProxy/*)` checks for the header that indicates an https request.
  - `$SETPROXY(127.0.0.1:8081)` is executed when found.
  - `(^)` expression never matches. 

* Identify https connections by testing for the "Tagged" request header that the ProxHTTPSProxy front server adds to the request. 

  `$OHDR(Tagged:ProxHTTPSProxyMII FrontProxy/*)`

* For local file requests, use an expression like 

  `$USEPROXY(false)$RDIR(http://local.ptron/killed.gif)`

* Before redirecting "Tagged" connections to external resources consider removing the "Tagged" header. 

* If needed, the Proxomitron can still do https. After adding the ssl files to the Proxomitron, use a header filter like

  ```
  [HTTP headers]
  In = FALSE
  Out = TRUE
  Key = "Tagged: Use Proxomitron for https://badcert.com"
  URL = "badcert.com$OHDR(Tagged:ProxHTTPSProxyMII FrontProxy/*)$USEPROXY(false)$RDIR(https://badcert.com)"
  ```
  This filter also removes the "Tagged" header. 

For the current sidki set
----

1. Add the following two lines to Exceptions-U

  ```
  $OHDR(Tagged:ProxHTTPSProxyMII FrontProxy/*)$SET(keyword=$GET(keyword)i_proxy:3.)(^)
  ~(^$TST(keyword=i_proxy:[03].))$OHDR(Tagged:ProxHTTPSProxyMII FrontProxy/*)$SET(keyword=$GET(keyword)i_proxy:3.)(^)
  ```

2. Redirect connections to http resources with an expression like

  `$USEPROXY(false)$SET(keyword=i_proxy:0.)$RDIR(http://local.ptron/killed.gif)`
