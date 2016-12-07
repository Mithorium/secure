# Secure-fasthttp [![GoDoc](https://godoc.org/github.com/Mithorium/secure-fasthttp?status.svg)](http://godoc.org/github.com/Mithorium/secure-fasthttp) [![Build Status](https://travis-ci.org/Mithorium/secure-fasthttp.svg)](https://travis-ci.org/Mithorium/secure-fasthttp)

Secure-fasthttp is a HTTP middleware for Go forked from [unrolled/secure](https://github.com/unrolled/secure) that facilitates some quick security wins. It is meant to be used with [valyala/fasthttp](https://github.com/valyala/fasthttp).

## Usage

~~~ go
// main.go
package main

import (
    "fmt"
    "log"

    "github.com/valyala/fasthttp"
    "github.com/mithorium/secure-fasthttp"
)

func requestHandler(ctx *fasthttp.RequestCtx) {
    fmt.Fprintf(ctx, "Hello, world!\n")
}

func main() {
    secureMiddleware := secure.New(secure.Options{
        AllowedHosts:          []string{"example.com", "ssl.example.com"},
        SSLRedirect:           true,
        SSLHost:               "ssl.example.com",
        SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
        STSSeconds:            315360000,
        STSIncludeSubdomains:  true,
        STSPreload:            true,
        FrameDeny:             true,
        ContentTypeNosniff:    true,
        BrowserXssFilter:      true,
        ContentSecurityPolicy: "default-src 'self'",
        PublicKey:             `pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; max-age=5184000; includeSubdomains; report-uri="https://www.example.com/hpkp-report"`,
    })

    secureHandler := secureMiddleware.Handler(requestHandler)
    if err := fasthttp.ListenAndServe(":8080", secureHandler); err != nil {
        log.Fatalf("Error in ListenAndServe: %s", err)
    }
}
~~~

Be sure to include the Secure middleware as close to the top (beginning) as possible (but after logging and recovery). It's best to do the allowed hosts and SSL check before anything else.

The above example will only allow requests with a host name of 'example.com', or 'ssl.example.com'. Also if the request is not HTTPS, it will be redirected to HTTPS with the host name of 'ssl.example.com'.
Once those requirements are satisfied, it will add the following headers:
~~~ go
Strict-Transport-Security: 315360000; includeSubdomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
PublicKey: pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; max-age=5184000; includeSubdomains; report-uri="https://www.example.com/hpkp-report"
~~~

###Set the `IsDevelopment` option to `true` when developing!
When `IsDevelopment` is true, the AllowedHosts, SSLRedirect, STS header, and HPKP header will not be in effect. This allows you to work in development/test mode and not have any annoying redirects to HTTPS (ie. development can happen on HTTP), or block `localhost` has a bad host.

### Available options
Secure comes with a variety of configuration options (Note: these are not the default option values. See the defaults below.):

~~~ go
// ...
s := secure.New(secure.Options{
    AllowedHosts: []string{"ssl.example.com"}, // AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
    SSLRedirect: true, // If SSLRedirect is set to true, then only allow HTTPS requests. Default is false.
    SSLTemporaryRedirect: false, // If SSLTemporaryRedirect is true, the a 302 will be used while redirecting. Default is false (301).
    SSLHost: "ssl.example.com", // SSLHost is the host name that is used to redirect HTTP requests to HTTPS. Default is "", which indicates to use the same host.
    SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"}, // SSLProxyHeaders is set of header keys with associated values that would indicate a valid HTTPS request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
    STSSeconds: 315360000, // STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
    STSIncludeSubdomains: true, // If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
    STSPreload: true, // If STSPreload is set to true, the `preload` flag will be appended to the Strict-Transport-Security header. Default is false.
    ForceSTSHeader: false, // STS header is only included when the connection is HTTPS. If you want to force it to always be added, set to true. `IsDevelopment` still overrides this. Default is false.
    FrameDeny: true, // If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
    CustomFrameOptionsValue: "SAMEORIGIN", // CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option.
    ContentTypeNosniff: true, // If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
    BrowserXssFilter: true, // If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
    ContentSecurityPolicy: "default-src 'self'", // ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "".
    PublicKey: `pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; max-age=5184000; includeSubdomains; report-uri="https://www.example.com/hpkp-report"`, // PublicKey implements HPKP to prevent MITM attacks with forged certificates. Default is "".
    
    IsDevelopment: true, // This will cause the AllowedHosts, SSLRedirect, and STSSeconds/STSIncludeSubdomains options to be ignored during development. When deploying to production, be sure to set this to false.
})
// ...
~~~

### Default options
These are the preset options for Secure:

~~~ go
s := secure.New()

// Is the same as the default configuration options:

l := secure.New(secure.Options{
    AllowedHosts: []string,
    SSLRedirect: false,
    SSLTemporaryRedirect: false,
    SSLHost: "",
    SSLProxyHeaders: map[string]string{},
    STSSeconds: 0,
    STSIncludeSubdomains: false,
    STSPreload: false,
    ForceSTSHeader: false,
    FrameDeny: false,
    CustomFrameOptionsValue: "",
    ContentTypeNosniff: false,
    BrowserXssFilter: false,
    ContentSecurityPolicy: "",
    PublicKey: "",
    IsDevelopment: false,
})
~~~
Also note the default bad host handler throws an error:
~~~ go
func defaultBadHostHandler(ctx *fasthttp.RequestCtx) {
	ctx.Error("Bad Host", fasthttp.StatusInternalServerError)
}
~~~
Call `secure.SetBadHostHandler` to change the bad host handler.

### Redirecting HTTP to HTTPS
If you want to redirect all HTTP requests to HTTPS, you can use the following example.

~~~ go
// main.go
package main

import (
    "fmt"
    "log"
    "github.com/valyala/fasthttp"
    "github.com/mithorium/secure-fasthttp"
)

func requestHandler(ctx *fasthttp.RequestCtx) {
    fmt.Fprintf(ctx, "Hello, world!\n")
}

func main() {
    secureMiddleware := secure.New(secure.Options{
        SSLRedirect: true,
        SSLHost:     "localhost:8443", // This is optional in production. The default behavior is to just redirect the request to the HTTPS protocol. Example: http://github.com/some_page would be redirected to https://github.com/some_page.
    })

    secureHandler := secureMiddleware.Handler(requestHandler)

    // HTTP
    go func() {
        log.Fatal(fasthttp.ListenAndServe(":8080", secureHandler))
    }()

    // HTTPS
    // To generate a development cert and key, run the following from your *nix terminal:
    // go run $GOROOT/src/pkg/crypto/tls/generate_cert.go --host="localhost"
    log.Fatal(fasthttp.ListenAndServeTLS(":8443", "cert.pem", "key.pem", secureHandler))
}
~~~

### Strict Transport Security
The STS header will only be sent on verified HTTPS connections (and when `IsDevelopment` is false). Be sure to set the `SSLProxyHeaders` option if your application is behind a proxy to ensure the proper behavior. If you need the STS header for all HTTP and HTTPS requests (which you [shouldn't](http://tools.ietf.org/html/rfc6797#section-7.2)), you can use the `ForceSTSHeader` option. Note that if `IsDevelopment` is true, it will still disable this header even when `ForceSTSHeader` is set to true.

* The `preload` flag is required for domain inclusion in Chrome's [preload](https://hstspreload.appspot.com/) list.

### Content Security Policy
If you need dynamic support for CSP while using Websockets, check out this other middleware [awakenetworks/csp](https://github.com/awakenetworks/csp).  

## Nginx
If you would like to add the above security rules directly to your [Nginx](http://wiki.nginx.org/Main) configuration, everything is below:
~~~
# Allowed Hosts:
if ($host !~* ^(example.com|ssl.example.com)$ ) {
    return 500;
}

# SSL Redirect:
server {
    listen      80;
    server_name example.com ssl.example.com;
    return 301 https://ssl.example.com$request_uri;
}

# Headers to be added:
add_header Strict-Transport-Security "max-age=315360000";
add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'";
add_header Public-Key-Pins 'pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; max-age=5184000; includeSubdomains; report-uri="https://www.example.com/hpkp-report"';
~~~
