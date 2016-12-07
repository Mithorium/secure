/*Package secure is an HTTP middleware for Go that facilitates some quick security wins.

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
      FrameDeny:             true,
      ContentTypeNosniff:    true,
      BrowserXssFilter:      true,
    })

    secureHandler := secureMiddleware.Handler(requestHandler)
    if err := fasthttp.ListenAndServe(":8080", secureHandler); err != nil {
      log.Fatalf("Error in ListenAndServe: %s", err)
    }
  }
*/
package secure
