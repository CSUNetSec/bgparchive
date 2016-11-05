package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"log"
)

const (
	GET     = "GET"
	PUT     = "PUT"
	POST    = "POST"
	DELETE  = "DELETE"
)

//we now need to wrap the integer HTTP Reply code in this struct
//to be able to support the correct ID for the continuous pulling scheme
type HdrReply struct {
	Code  int
	Extra string
}

type Reply struct {
	Data []byte
	Err  error
}

type Resource interface {
	Get(url.Values) (HdrReply, chan Reply)
	Put(url.Values) (HdrReply, chan Reply)
	Post(url.Values) (HdrReply, chan Reply)
	Delete(url.Values) (HdrReply, chan Reply)
}

type (
	GetNotAllowed    struct{}
	PutNotAllowed    struct{}
	PostNotAllowed   struct{}
	DeleteNotAllowed struct{}
)

func (GetNotAllowed) Get(vals url.Values) (HdrReply, chan Reply) {
	return HdrReply{Code: 405}, nil
}

func (PutNotAllowed) Put(vals url.Values) (HdrReply, chan Reply) {
	return HdrReply{Code: 405}, nil
}

func (PostNotAllowed) Post(vals url.Values) (HdrReply, chan Reply) {
	return HdrReply{Code: 405}, nil
}

func (DeleteNotAllowed) Delete(vals url.Values) (HdrReply, chan Reply) {
	return HdrReply{Code: 405}, nil
}

type API struct {
	mux *http.ServeMux
}

func NewAPI() *API {
	return &API{http.NewServeMux()}
}

func (api *API) requestHandlerFunc(resource Resource) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		var (
			datac chan Reply
			code  HdrReply
		)
		log.Printf("--Request From:%s --", req.RemoteAddr)
		req.ParseForm()
		method := req.Method
		vals := req.Form
		//here i plug the remote address in the vals map for the Get function to have
		ip := strings.Split(req.RemoteAddr, ":") //split cause it's ip:port
		vals["remoteaddr"] = ip
		switch method {
		case GET:
			code, datac = resource.Get(vals)
		case PUT:
			code, datac = resource.Put(vals)
		case POST:
			code, datac = resource.Post(vals)
		case DELETE:
			code, datac = resource.Delete(vals)
		}
		if code.Extra != "" { //he have a uuid for continuous pulling
			rw.Header().Set("Next-Pull-ID", code.Extra)
		}
		//set the CORS header
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		rw.WriteHeader(code.Code)
		if datac != nil { // we got a proper channel to get datafrom
			//go func(dc <-chan Reply) { // fire a goroutine that will end upon the chan getting closed
			for r := range datac {
				if r.Err == nil {
					rw.Write(r.Data)
				} else {
					log.Printf("Error in received from data channel:%s\n", r.Err)
					rw.Write([]byte(fmt.Sprintf("%s\n", r.Err)))
				}
			}
			//}(datac)
		}
	}
}

func (api *API) AddResource(resource Resource, path string) {
	api.mux.HandleFunc(path, api.requestHandlerFunc(resource))
}

func (api *API) Start(port int) {
	portstr := fmt.Sprintf(":%d", port)
	http.ListenAndServe(portstr, api.mux)
}
