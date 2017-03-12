package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	GET    = "GET"
	PUT    = "PUT"
	POST   = "POST"
	DELETE = "DELETE"
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
	Get(context.Context, url.Values) (HdrReply, chan Reply)
	Put(context.Context, url.Values) (HdrReply, chan Reply)
	Post(context.Context, url.Values) (HdrReply, chan Reply)
	Delete(context.Context, url.Values) (HdrReply, chan Reply)
}

type (
	GetNotAllowed    struct{}
	PutNotAllowed    struct{}
	PostNotAllowed   struct{}
	DeleteNotAllowed struct{}
)

func (GetNotAllowed) Get(ctx context.Context, vals url.Values) (HdrReply, chan Reply) {
	return HdrReply{Code: 405}, nil
}

func (PutNotAllowed) Put(ctx context.Context, vals url.Values) (HdrReply, chan Reply) {
	return HdrReply{Code: 405}, nil
}

func (PostNotAllowed) Post(ctx context.Context, vals url.Values) (HdrReply, chan Reply) {
	return HdrReply{Code: 405}, nil
}

func (DeleteNotAllowed) Delete(ctx context.Context, vals url.Values) (HdrReply, chan Reply) {
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
		ctx, cf := context.WithCancel(context.Background())
		log.Printf("--Request From:%s --", req.RemoteAddr)
		req.ParseForm()
		method := req.Method
		vals := req.Form
		//here i plug the remote address in the vals map for the Get function to have
		ip := strings.Split(req.RemoteAddr, ":") //split cause it's ip:port
		vals["remoteaddr"] = ip
		switch method {
		case GET:
			code, datac = resource.Get(ctx, vals)
		case PUT:
			code, datac = resource.Put(ctx, vals)
		case POST:
			code, datac = resource.Post(ctx, vals)
		case DELETE:
			code, datac = resource.Delete(ctx, vals)
		}
		if code.Extra != "" { //he have a uuid for continuous pulling
			rw.Header().Set("Next-Pull-ID", code.Extra)
		}
		//set the CORS header
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		rw.WriteHeader(code.Code)
		if datac != nil { // we got a proper channel to get datafrom
			//go func(dc <-chan Reply) { // fire a goroutine that will end upon the chan getting closed
			reqOpen := true
			for reqOpen {
				select {
				case r, reqOpen := <-datac:
					if reqOpen {
						if r.Err == nil {
							rw.Write(r.Data)
						} else {
							log.Printf("Error in received from data channel:%s\n", r.Err)
							rw.Write([]byte(fmt.Sprintf("%s\n", r.Err)))
						}
					}
				case <-rw.(http.CloseNotifier).CloseNotify():
					cf()
					reqOpen = false
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
