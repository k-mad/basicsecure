# basicsecure

Golang wrapper with hard coded security headers and checking for authorized hosts.\
If you're looking for something more robust, try [unrolled/secure](https://github.com/unrolled/secure).

## Limitations

- This code probably won't work for you as is; however, it's simple enough to copy and customize.
- Designed to be used with Heroku.
- Any http request is redirected to https to r.Host without any parts of the path because of issues with GoDaddy forwarding.
- The directives are too strict for sites that serve resources from a CDN.

## Usage

~~~ go
package main

import (
    "net/http"
    "os"

    "github.com/k-mad/basicsecure"
)

func inTesting() bool {
    testing := os.Getenv("MY_APP_TESTING")
    if testing == "true" {
        return true
    }
    return false
}

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("hello world"))
})

func main() {
    bs := basicsecure.BasicSecure{
        AllowedHosts: []string{"example.com", "www.example.com"},
        Testing:      inTesting(),
    }
    http.ListenAndServe("127.0.0.1:8080", bs.Handler(myHandler))
}
~~~