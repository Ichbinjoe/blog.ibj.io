---
title: "Securing services with multiple routing paths"
date: 2019-03-22T00:17:29-04:00
tags: [linux, sysadmin, x509]
---

LetsEncrypt is really helpful for properly securing services. Obviously, this is
a topic thats been beaten to death by countless other people, so I'll try to
tread lightly on the details of LE specifically and jump straight to my use and
solution.

My problem is a bit more grand than I need TLS certificates - I've been using
TLS certificates from LetsEncrypt for some time now, but the way I used to have
external traffic routing into my homelab made it difficult to also sign traffic
coming from within my homelab.

To be more plain, imagine the following scenario: I have a rack of servers in my
basement. They all sit on the same network that my desktop, laptop, and wifes
things sit on. There is some VLAN and routing magic in there, but thats not
important for now. From this jumbling of servers I want to serve some services
(like a binary repository for tons of Java things) however I need to also be
able to use the services from the LAN.

Now this doesn't sound bad, except for two things - because of poor planning,
the hostnames in my network are identical to the hostnames outside of my
network. This is partially ok because I don't want traffic to leave my network
when it doesn't have to. However, my second mistake comes with how I terminated
TLS traffic. In order to route to multiple services from one public IP, I needed
to terminate all TLS traffic at one Nginx instance. This meant that this Nginx
contained all of my certificates, but I was still locally going straight to the
service. This was a problem because if I wanted to secure my local connection, I
would have to obtain a duplicate certificate from LetsEncrypt or copy of the
certificate created on the head Nginx instance. It is bad practice to copy
private keys over any medium if it can be avoided. In addition, this would have
had to be done every time the certificate was renewed every 3 months. Minting
additional certificates didn't make me feel good, so for a long time services
inside of my network went unsecured.

## What I want

Today, I devised that I was going to shake up my network and fix these data
routing problems once and for all. Some of the things I wanted to do:

+ No matter what network I was on (internal, external, via VPN, via dn42, etc) I
  would be able to gain a publicly trusted https connection to services.
+ The service needs to be forwarded in some way the original IP of the
  requester, whether it be the actual IP or via some other means
  (X-Forwarded-For)
+ The service should be the TLS termination of the connection
+ The service is the only one that holds the private key

Some of these goals are pretty lofty, but achievable.

## Enter HAProxy

I decided to replace my Nginx external connection termination server with
HAProxy. Here are some of the traits that made me choose HAProxy:

+ HAProxy deals natively with HTTP, TLS, and TCP
+ HAProxy incorporates the PROXY protocol
+ HAProxy can read the SNI field of a TLS connection

For the uninitiated, the PROXY protocol is a super simple protocol developed by
HAProxy for the intent of forwarding source IP information along to the
destination at the beginning of the TCP stream. This is a breaking change if the
destination server is not prepared to take it, but we account for that later.

I need SNI which was really the primary driving force behind choosing HAProxy. I
found a cool blog post at
[scriptthe.net](https://scriptthe.net/2015/02/08/pass-through-ssl-with-haproxy/)
that describes the basic settings in HAProxy I would need. This is the first
time I've worked with HAProxy, so I needed a bit of help getting the right
behavior.

## What is SNI

Server name indication is an optional extension to the TLS client hello
handshake. This indicates to the destination server what server the client is
actually looking for. This assists the server in handing back the correct
certificate for the correct website, especially when multiple websites sit
behind the same IP. Without this field, the destination server would have no
idea who the client was trying to talk to.

We will leverage this by telling HAProxy to read this extension to determine our
backend server - just as it was intended!

## Fitting HAProxy into the entire system

As noted above, the PROXY protocol breaks all protocols that aren't expecting it
(who would have guessed). Thankfully, nginx understands the PROXY protocol and
can mutate the request through proxypass to add the X-Forwarded-For header so
that applications which care and support this header will be able to get the
client's original IP. This would be fine except for my desktop and other devices
within my network not going through HAProxy don't support the PROXY protocol.

## Final architecture

Each service was fronted by Nginx on the same container which handled TLS
termination. The Nginx would open 4 ports - 80, 81, 443, and 444. 80 and 443 act
as the traditional HTTP and HTTPS ports, while 81 and 444 act as HTTP+PROXY and
HTTPS+PROXY ports specifically for HAProxy to hit. Originally I wanted this to
be on its own VLAN, but I deemed that to be more complicated than what it was
worth. HAProxy would be set up to listen on 80 and 443. On 80, HAProxy would
perform normal host identification on the HTTP header and forward the traffic
along to port 81 of the respective port. On 443, HAProxy would sniff the SNI
extension and forward the TCP connection to port 444 of the respective service,
allowing the service to terminate its own TLS connection.

This solution satisfies the four goals I had above.

## How does LetsEncrypt fit into this?

LetsEncrypt is now able to run on each of the service's containers
independently! Each service handles its own updating of expired certificates and
has the correct hooks to reload nginx when new certificates are signed. Because
we pass through both HTTP and HTTPS to the backend services, the ACME http-01
challenge works as expected even through my NAT and HAProxy.

## Configuration dump

Here is the part where you get your prime copy paste material:

Backend service nginx configuration located at
`/etc/nginx/sites-enabled/default`:

```nginx
server {
        listen 80;
        listen 81 proxy_protocol;

        server_name grafana.ibj.io;
        location /.well-known {
                root /var/www/html/;
        }

        location / {
                return 301 https://$server_name$request_uri;
        }
}
server {
        listen 443 ssl;
        listen 444 ssl proxy_protocol;

        ssl_certificate /etc/letsencrypt/live/grafana.ibj.io/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/grafana.ibj.io/privkey.pem;

        # Reference: https://gist.github.com/gavinhungry/7a67174c18085f4a23eb
        ssl_dhparam /etc/ssl/ffdhe4096.pem;

        ssl_protocols TLSv1.3 TLSv1.2 TLSv1.1 TLSv1;
        ssl_prefer_server_ciphers on;
        ssl_ciphers EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA512:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:ECDH+AESGCM:ECDH+AES256:DH+AESGCM:DH+AES256:RSA+AESGCM:!aNULL:!eNULL:!LOW:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS;

        ssl_session_cache shared:TLS:2m;
        ssl_buffer_size 4k;

        ssl_stapling on;
        ssl_stapling_verify on;

        resolver 1.1.1.1 1.0.0.1 [2606:4700:4700::1111] [2606:4700:4700::1001]; # Cloudflare
        add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;

        server_name grafana.ibj.io;

        location / {
                proxy_pass http://localhost:3000;
        }
}
```

This nginx config pushes users to https, while leaves the ACME location of http
available so that the http-01 challenge may occur when certificates need
updating.

This includes the STS header as well as SSL stapling.

Now at first, you will either need to load in the snakeoil certificates or
comment out the 443/444 server block because the certificates don't exist. Once
you run LE for the first time you can go back in and uncomment that block.

Now this requires an additional modified DHParams file at
`/etc/ssl/ffdhe4096.pem`:

```
-----BEGIN DH PARAMETERS-----
MIICCAKCAgEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEfz9zeNVs7ZRkDW7w09N75nAI4YbRvydbmyQd62R0mkff3
7lmMsPrBhtkcrv4TCYUTknC0EwyTvEN5RPT9RFLi103TZPLiHnH1S/9croKrnJ32
nuhtK8UiNjoNq8Uhl5sN6todv5pC1cRITgq80Gv6U93vPBsg7j/VnXwl5B0rZp4e
8W5vUsMWTfT7eTDp5OWIV7asfV9C1p9tGHdjzx1VA0AEh/VbpX4xzHpxNciG77Qx
iu1qHgEtnmgyqQdgCpGBMMRtx3j5ca0AOAkpmaMzy4t6Gh25PXFAADwqTs6p+Y0K
zAqCkc3OyX3Pjsm1Wn+IpGtNtahR9EGC4caKAH5eZV9q//////////8CAQI=
-----END DH PARAMETERS-----
```

This 4096 bit DHE groups are recommended by
[RFC7919](https://tools.ietf.org/html/rfc7919) as well as
[Mozilla](https://wiki.mozilla.org/Security/Server_Side_TLS#ffdhe4096).



Now on to HAProxy. I clipped out the global and defaults sections. This file is
located at `/etc/haproxy/haproxy.cfg` on my Ubuntu install.

```nginx
frontend http-in
        bind *:80

        acl host_grafana hdr(host) -i grafana.ibj.io

        use_backend grafana-plain if host_grafana

frontend https-in
        mode tcp
        option tcplog
        bind *:443

        tcp-request inspect-delay 5s
        tcp-request content accept if { req_ssl_hello_type 1 }

        use_backend grafana-tls if { req_ssl_sni -i grafana.ibj.io }

backend grafana-plain
        mode http
        option httplog

        server grafana grafana.ibj.io:81 send-proxy-v2

backend grafana-tls
        mode tcp
        option tcplog

        acl clienthello req_ssl_hello_type 1
        acl serverhello req_ssl_hello_type 2

        tcp-request inspect-delay 5s
        tcp-request content accept if clienthello
        tcp-request content accept if serverhello

        stick-table type binary len 32 size 30k expire 30m

        stick on payload_lv(43,1) if clienthello
        stick store-response payload_lv(43,1) if serverhello

        server grafana grafana.ibj.io:444 send-proxy-v2
```


To mint certificates, I ran the following command:

```
certbot certonly --webroot -w /var/www/html -d grafana.ibj.io
```

There are some additional flags I could have added to make it so that it didn't
ask me a bunch of questions, but I don't mind.

Now I wanted to never touch this box again (in regards to new certs). Distros
have gotten good and automatically put certbot within a systemd timer - I also
read up that you can add a script to `/etc/letsencrypt/renewal-hooks/deploy` to
be run after a script has been newly renewed.

Thus I added `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx`:

```sh
#!/bin/sh
nginx -s reload
```

This will tell nginx to reload after we get our new certificates. Of important
note, this file must be marked executable: `chmod +x
/etc/letsencrypt/renewal-hooks/deploy/reload-nginx`. Time will tell if this hook
works!
