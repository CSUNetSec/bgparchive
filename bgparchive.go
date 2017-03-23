package bgparchive

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/CSUNetSec/bgparchive/api"
	util "github.com/CSUNetSec/bgparchive/util"
	pb "github.com/CSUNetSec/netsec-protobufs/protocol/bgp"
	pp "github.com/CSUNetSec/protoparse"
	ppmrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	"github.com/golang/protobuf/proto"
	"github.com/rogpeppe/fastuuid"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	HELPSTR = `
					Welcome to the BGPMon.io archive
					================================
	This archive serves data from BGP collectors around the world operated by RouteViews and BGPMon.io.

	The interface supports data retrieval based on a timerange. You may retrieve (a) BGP update messages in various formats, indluding MRT, JSON and protocol buffers, (b) BGP RIBs or (c) BGP update message statistics.
	The protocol buffer specification can be found at: https://github.com/CSUNetSec/netsec-protobufs/blob/master/bgpmon/bgpmon.proto (message BGPCapture).

	IMPORTANT NOTE: BGP data can be large. For example, one hour's worth of updates from routeviews2 can be around 8MB. RIBs are larger. Please exercise care when making requests for long time ranges.

	Start and end times are specified in the YYYMMDDMMSS format.

	Below are examples of how to use the interface. You may fetch data from one collector at a time. All examples below fetch data from the routeviews2 collector (currently the largest collector).

	Run the following first to get this help message, a current list of available collectors and the time range they serve:
	curl http://bgpmon.io/archive/help

	Fetch updates in MRT format from 01/01/2013 00:00:00 to 01/01/2013 01:00:00 UTC:
	curl -o updates http://bgpmon.io/archive/mrt/routeviews2/updates?start=20130101000000\&end=20130101010000

	Fetch updates in JSON format from 01/01/2013 00:00:00 to 01/01/2013 01:00:00 UTC:
	curl -o updates http://bgpmon.io/archive/json/routeviews2/updates?start=20130101000000\&end=20130101010000

	Fetch updates as protocol buffers from 01/01/2013 00:00:00 to 01/01/2013 01:00:00 UTC:
	curl -o updates http://bgpmon.io/archive/pb/routeviews2/updates?start=20130101000000\&end=20130101010000

	Start a continuous pull for updates. The HTTP return header contains the UUID for each consecutive pull under the field Next-Pull-ID:
	curl -v http://bgpmon.io/archive/mrt/routeviews2/updates?continuous=begin

	Specify a start time in continuous mode. This will bring everything from the specified start time until the time of the request, including an ID to use for the next request:
	curl -v http://bgpmon.io/archive/mrt/routeviews2/updates?continuous=begin\&start=20151105000000

	Then once we get the id:
	curl -v -o updates http://bgpmon.io/archive/mrt/routeviews2/updatescontinuous=115786068dca20709955f88faa71d241
	Note that the state will timeout after 30 minutes of inactivity and you will need to start a new session.

	Fetch all RIBs exported from 01/01/2013 00:00:00 to 01/01/2013 01:00:00 UTC:
	curl -o ribs http://bgpmon.io/archive/mrt/routeviews2/ribs?start=20130101000000\&end=20130101010000

	See the date range of a particular collector:
	curl http://bgpmon.io/archive/mrt/routeviews2/updates/conf?range

	Get the original MRT file names from the the archive back end:
	curl http://bgpmon.io/archive/mrt/routeviews2/updates/conf?files

	Get JSON-encoded statistics about the requested time range in the following format:
	<# of all types of all messages in the requested time range>
	followed by a matrix with three rows and a # columns equal to the number of seconds in the requested interval
	row 0 - # of all types messages: <# of all types of messages at sec 0>, <# of all messages at sec 1>, ...
	row 1 - # of MPReach   messages: <# of MPReach messages at sec 0>, <# of MPReach at sec 1>, ...
	row 2 - # of MPUnreach messages: <# of MPUnreach messages at sec 0>, <# of MPUnreach messages at sec 1>, ...

	curl http://bgpmon.io/archive/mrt/routeviews2/updates/stats?start=20160101000000\&end=20160101010000

	Collectors and their time range:

	`
)

var (
	errbadreq  = errors.New("malformed request")
	errbaddate = errors.New("dates should be in a YYYYMMDDHHMMSS format and start should be earlier than end")
	errempty   = errors.New("archive empty")
	errdate    = errors.New("no such date in archive")
	errbigdt   = errors.New("The requested duration is too large. Try something smaller than 24h")
	errnoar    = errors.New("no such archive")
)

type HelpMsg struct {
	ars []*fsarconf
	api.PutNotAllowed
	api.PostNotAllowed
	api.DeleteNotAllowed
}

func (h *HelpMsg) Get(values url.Values) (api.HdrReply, chan api.Reply) {
	retc := make(chan api.Reply)
	go func(rch chan api.Reply) {
		defer close(rch)
		rch <- api.Reply{Data: []byte(fmt.Sprintf("%s\n", HELPSTR)), Err: nil}
		for i := range h.ars {
			arstr := fmt.Sprintf("\t%-8s archive: %-25s\trange:%s", riborupdatestr(h.ars[i].descriminator), h.ars[i].GetCollectorString(), h.ars[i].GetDateRangeString())
			rch <- api.Reply{Data: []byte(arstr), Err: nil}
		}
		return
	}(retc)
	return api.HdrReply{Code: 200}, retc

}

func riborupdatestr(a string) string {
	switch a {
	case "table":
		return "ribs"
	}

	return strings.ToLower(a)
}

func (h *HelpMsg) AddArchive(ar *fsarconf) {
	h.ars = append(h.ars, ar)
}

type BgpStats struct {
	StartTime                                          string
	EndTime                                            string
	Delta_sec                                          int
	TotalMsgs                                          int64
	TotalPerDelta, Withdrawn, NLRI, MPReach, MPUnreach []int
}

//To perform a query asynchronously on possibly many files we fire multiple goroutines
//that all write their results to chan api.Reply, and we also need the waitgroup
//to know when we should close the channel to end the http transaction
type archive interface {
	Query(time.Time, time.Time, chan api.Reply, *sync.WaitGroup)
}

type contpuller interface {
	getContextChans() (chan contCmd, chan contCli)
}

type contarchive interface {
	archive
	contpuller
}

//implements Sort interface by time.Time
type ArchEntryFile struct {
	Path  string
	Sdate time.Time
	Sz    int64
}

func (a ArchEntryFile) String() string {
	return fmt.Sprintf("[path:%s date:%v size:%d]", a.Path, a.Sdate, a.Sz)
}

type TimeEntrySlice []ArchEntryFile

func (a TimeEntrySlice) String() string {
	var ret []string
	for _, v := range a {
		ret = append(ret, v.String())
	}
	return strings.Join(ret, " ")
}

func (p TimeEntrySlice) Len() int {
	return len(p)
}

func (p TimeEntrySlice) Less(i, j int) bool {
	return p[i].Sdate.Before(p[j].Sdate)
}

func (p TimeEntrySlice) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

type fsarchive struct {
	rootpathstr    string
	entryfiles     TimeEntrySlice
	tempentryfiles TimeEntrySlice
	reqchan        chan string
	scanning       bool
	scanwg         *sync.WaitGroup
	scanch         chan struct{}
	timedelta      time.Duration
	descriminator  string
	refreshmin     int
	//this context will allow us to communicate with the continuous pull client goroutine
	contctx *contCtx
	//collector name that is used in the url as well as the saved index files
	collectorstr string
	debug        bool
	savepath     string
	//present the archive as a restful resource
	api.PutNotAllowed
	api.PostNotAllowed
	api.DeleteNotAllowed
}

func (f fsarchive) getContextChans() (chan contCmd, chan contCli) {
	return f.contctx.reqch, f.contctx.repch
}

func (f fsarchive) GetDateRangeString() string {
	if len(f.entryfiles) > 0 {
		files := f.entryfiles
		dates := fmt.Sprintf("%s - %s\n", files[0].Sdate, files[len(files)-1].Sdate)
		return dates
	}
	return "archive is empty\n"
}

func (f *fsarchive) ToGobFile(fname string) (err error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err = enc.Encode(f.entryfiles)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fname, buf.Bytes(), 0600)
	if err != nil {
		log.Printf("ToGobFile error:%s", err)
	}
	return
}

func (f *fsarchive) FromGobFile(fname string) (err error) {
	n, err := ioutil.ReadFile(fname)
	if err != nil {
		return
	}
	p := bytes.NewBuffer(n)
	dec := gob.NewDecoder(p)
	err = dec.Decode(&(f.entryfiles))
	if err != nil {
		log.Printf("FromGobFile error:%s", err)
	}
	return
}

func (f fsarchive) GetCollectorString() string {
	return f.collectorstr
}

//a context for the continuous pulling client communication with the serving goroutine
type contCli struct {
	t1pull time.Time
	t2pull time.Time
	ip     string
	id     string //the associated current id with this client
	err    error
	cchan  chan bool //the chan to cancel the timeout goroutine
}

type contCmd struct {
	cmd int
	cli contCli
}

const (
	CONT_ADD int = iota
	CONT_GET
	CONT_EXISTS
	CONTCLISZ = 100
)

type contCtx struct {
	contclis map[string][]*contCli //one ip can have up to CONTCLISZ contexts associated at any point
	contuuid map[string]*contCli
	reqch    chan contCmd
	repch    chan contCli
	ug       *fastuuid.Generator
}

func newContCtx() *contCtx {
	return &contCtx{
		contclis: make(map[string][]*contCli),
		contuuid: make(map[string]*contCli),
		reqch:    make(chan contCmd),
		repch:    make(chan contCli),
		ug:       fastuuid.MustNewGenerator(), //this may panic if the generator fails to generate ;)
	}
}

func (ctx *contCtx) Add(a *contCli) error {
	if a.ip == "" && a.id == "" {
		return errors.New("both arguments in Add empty")
	}
	if a.ip != "" {
		contexts, ok := ctx.contclis[a.ip]
		if ok {
			if len(contexts) >= CONTCLISZ {
				return errors.New("max handlers for this ip already registered")
			}
		} else {
			//first time the array for that IP is created
			ctx.contclis[a.ip] = []*contCli{}
		}
	}
	u := ctx.ug.Next()
	uhex := hex.EncodeToString(u[:16])
	a.t1pull = time.Now()
	a.id = uhex
	a.cchan = make(chan bool)
	ctx.contclis[a.ip] = append(ctx.contclis[a.ip], a)
	ctx.contuuid[a.id] = a
	ctx.PrintClis()
	return nil
}

func (ctx *contCtx) Del(a *contCli) error {
	var (
		vals []*contCli
		ok   bool
	)
	if a.ip == "" && a.id == "" {
		return errors.New("both arguments in Del empty")
	}
	if a.ip != "" {
		log.Printf("querying node :%+v by ip", a) //sanity check to ensure the ip is registered
		vals, ok = ctx.contclis[a.ip]
		if !ok {
			return errors.New("ip not registered")
		}
	} else if a.id != "" {
		log.Printf("removing node :%+v by id", a)
		_, ok = ctx.contuuid[a.id]
		if !ok {
			return errors.New("id not registered")
		}
	}
	for i := range vals {
		if vals[i].id == a.id {
			ctx.contclis[a.ip] = append(vals[:i], vals[i+1:]...)
		}
	}
	if len(ctx.contclis[a.ip]) == 0 { //last element was removed above
		delete(ctx.contclis, a.ip) //deregister this ip from the keys
	}
	delete(ctx.contuuid, a.id)
	ctx.PrintClis()
	return nil
}

func (ctx contCtx) ExistsId(a string) bool {
	_, ok := ctx.contuuid[a]
	return ok
}

func (ctx contCtx) ExistsIP(a string) bool {
	_, ok := ctx.contclis[a]
	return ok
}

func (ctx contCtx) GetIDsfromIP(a string) (ret []string) {
	cclis, ok := ctx.contclis[a]
	if ok {
		for i := range cclis {
			if cclis[i].ip == a {
				ret = append(ret, cclis[i].id)
			}
		}
	}
	return
}

// UpdateCli is based on the id existing in the argument. so only use it if you have checked for existance via id
func (ctx *contCtx) UpdateCli(a *contCli) {
	log.Printf("----before update")
	ctx.PrintClis()
	val := ctx.contuuid[a.id] //on the subsequent calls we need to use val because a is mostly empty for now.
	//val also contains the PREVIOUS id
	if val.t2pull.IsZero() { //first pull after start
		a.t1pull = val.t1pull
		a.t2pull = time.Now()
	} else { // we update both
		a.t1pull = val.t2pull
		a.t2pull = time.Now()
	}
	u := ctx.ug.Next()
	uhex := hex.EncodeToString(u[:16])
	a.id = uhex
	a.cchan = make(chan bool)
	delete(ctx.contuuid, val.id) //remove previous id
	for i := range ctx.contclis[val.ip] {
		if ctx.contclis[val.ip][i].id == val.id {
			ctx.contclis[val.ip][i] = a //update the value
		}
	}
	ctx.contuuid[a.id] = a // register new id
	log.Printf("----after update")
	ctx.PrintClis()
}

func (ctx contCtx) PrintClis() {
	log.Printf("PRINTING")
	for k, v := range ctx.contclis {
		log.Printf("by IP key:%v val:%v", k, v)
	}
	for k, v := range ctx.contuuid {
		log.Printf("by ID key:%v val:%v", k, v)
	}
}

func setTimer(a *contCli, expirech chan *contCli) {
	timer := time.NewTimer(30 * time.Minute)
	go func() {
		log.Printf("timer for context:%+v started", a)
		select {
		case <-timer.C:
			expirech <- a
		case <-a.cchan:
			timer.Stop()
			log.Printf("timer for context:%+v canceled", a)
		}
		return //this kills the goroutine
	}()
}

//serve just fires the goroutine that handles the continuous pulling
func (ctx contCtx) Serve() {
	//this is the goroutine that is the main event loop for the continuous pulling engine
	go func() {
		expirech := make(chan *contCli) //this is the aggregate channel that the timer goroutines will write their expiration
		for {
			select {
			case cmd := <-ctx.reqch:
				log.Printf("i got cmd:%+v with arg:%+v", cmd.cmd, cmd.cli)
				switch cmd.cmd {
				case CONT_ADD:
					err := ctx.Add(&cmd.cli)
					if err != nil {
						log.Printf("error :%s with cli:%+v", err, cmd.cli)
						ctx.repch <- contCli{err: err}
					} else {
						setTimer(&cmd.cli, expirech)
						log.Printf("cont event loop firing new timer with id:%s", cmd.cli.id)
						ctx.repch <- cmd.cli
					}

				case CONT_GET, CONT_EXISTS:
					log.Printf("querying for id:%s", cmd.cli.id)
					if ctx.ExistsId(cmd.cli.id) {
						log.Printf("FOUND by id")
						oval := ctx.contuuid[cmd.cli.id]
						oval.cchan <- true
						ctx.UpdateCli(&cmd.cli) // UpdateCli is based on the id existing in the argument. so only use it if you have checked for existance via id
						setTimer(&cmd.cli, expirech)
					} else if ctx.ExistsIP(cmd.cli.ip) {
						cmd.cli.err = errors.New(fmt.Sprintf("ip has a handler registered but this id is NX. current IDs associated with your ip are %v", ctx.GetIDsfromIP(cmd.cli.ip)))
						log.Printf("%s", cmd.cli.err)
					} else {
						cmd.cli.err = errors.New("non existant ID")
						log.Printf("%s", cmd.cli.err)
					}
					ctx.repch <- cmd.cli
				}

			case expcli := <-expirech:
				log.Printf("timer for:%+v expired. removing", expcli)
				err := ctx.Del(expcli)
				if err != nil {
					log.Printf("Del error :%s with cli:%+v", err, expcli)
					ctx.repch <- contCli{err: err}
				}
			}
		}
	}()
}

//XXX: not sure if we need to redeclare the not alloweds since we embed.
type mrtarchive struct {
	*fsarchive
	api.PutNotAllowed
	api.PostNotAllowed
	api.DeleteNotAllowed
}

//pbarchive is an fsarcihve that calls the protobuf transformer on query
type pbarchive struct {
	*fsarchive
}

type jsonarchive struct {
	*fsarchive
}

func NewPbArchive(a *fsarchive) *pbarchive {
	return &pbarchive{a}
}

func NewJsonArchive(a *fsarchive) *jsonarchive {
	return &jsonarchive{a}
}

type MrtArchives []*mrtarchive

func (m mrtarchive) GetFsArchive() *fsarchive {
	return m.fsarchive
}

func (m mrtarchive) GetScanWaitGroup() *sync.WaitGroup {
	return m.scanwg
}

func (m *mrtarchive) Save(a string) error {
	return m.ToGobFile(a)
}

func (m *mrtarchive) Load(a string) error {
	return m.FromGobFile(a)
}

func (m mrtarchive) GetReqChan() chan string {
	return m.reqchan
}

func (m *mrtarchive) StoreTempEntryFiles() {
	m.entryfiles = make(TimeEntrySlice, len(m.tempentryfiles))
	copy(m.entryfiles, m.tempentryfiles)
}

func (m *mrtarchive) mergeTempEntryWithEntryFiles() {
	lef := len(m.entryfiles)
	for i, tef := range m.tempentryfiles {
		earliestDate := tef.Sdate                           //get the earliest date (it's a sorted array)
		if m.entryfiles[lef-1].Sdate.Before(earliestDate) { //we need to merge
			m.entryfiles = append(m.entryfiles, m.tempentryfiles[i:]...)
			break
		}
	}
}

type fsarconf struct {
	*fsarchive
	api.PutNotAllowed
	api.PostNotAllowed
	api.DeleteNotAllowed
}

type fsarstat struct {
	*fsarchive
	api.PutNotAllowed
	api.PostNotAllowed
	api.DeleteNotAllowed
}

func NewFsarstat(a *fsarchive) *fsarstat {
	return &fsarstat{fsarchive: a}
}

func NewFsarconf(a *fsarchive) *fsarconf {
	return &fsarconf{fsarchive: a}
}

//in order not to block in gets, we need to
//fire a new goroutine to send the api.Reply on the channel
//the reason is that we create the channel here and we must
//return it to the responsewriter and any sends would block
//without the receiver being ready.
func (fsc fsarconf) Get(values url.Values) (api.HdrReply, chan api.Reply) {
	retc := make(chan api.Reply)
	go func() {
		defer close(retc) //must close the chan to let the listener finish.
		arfiles := fsc.fsarchive.entryfiles
		if arfiles == nil {
			log.Printf("nil arfile in fsarconf. ignoring request\n")
			return
		}
		if _, ok := values["range"]; ok {
			if len(arfiles) > 0 {
				f := arfiles
				dates := fmt.Sprintf("%s - %s\n", f[0].Sdate, f[len(f)-1].Sdate)
				retc <- api.Reply{Data: []byte(dates), Err: nil}
				return
			}
			retc <- api.Reply{Data: nil, Err: errempty}
			return
		}
		if _, ok := values["files"]; ok {
			for _, f := range arfiles {
				retc <- api.Reply{Data: []byte(fmt.Sprintf("%s\n", filepath.Base(f.Path))), Err: nil}
			}
			return
		}
		return
	}()
	return api.HdrReply{Code: 200}, retc
}

func getTimerange(values url.Values, ar archive, h api.HdrReply) (api.HdrReply, chan api.Reply) {
	var (
		grwg sync.WaitGroup
	)
	retc := make(chan api.Reply)
	timeAstrs, ok1 := values["start"]
	timeBstrs, ok2 := values["end"]
	if len(timeAstrs) != len(timeBstrs) || !ok1 || !ok2 {
		grwg.Add(1)
		go func() { defer grwg.Done(); retc <- api.Reply{Data: nil, Err: errbadreq} }()
		goto done
	}
	for i := 0; i < len(timeAstrs); i++ {
		log.Printf("timeAstr:%s timeBstr:%s .Current server time:%v", timeAstrs[i], timeBstrs[i], time.Now())
		timeA, errtime := time.Parse("20060102150405", timeAstrs[i])
		timeB, errtime1 := time.Parse("20060102150405", timeBstrs[i])
		log.Printf("1:%v %v", timeA, timeB)
		if errtime != nil || errtime1 != nil {
			log.Printf("date parse error A:%s B:%s", errtime, errtime1)
			grwg.Add(1)
			go func() {
				defer grwg.Done()
				retc <- api.Reply{Data: nil, Err: errors.New(fmt.Sprintf("%s .Current server time:%v", errbaddate, time.Now()))}
			}()
			goto done

		}
		if errtime != nil || timeB.Before(timeA) {
			log.Printf("warning: TimeB before TimeA")
			grwg.Add(1)
			go func() {
				defer grwg.Done()
				retc <- api.Reply{Data: nil, Err: errors.New(fmt.Sprintf("%s .Current server time:%v", errbaddate, time.Now()))}
			}()
		} else if timeA.AddDate(0, 0, 1).Before(timeB) {
			log.Printf("2:%v %v", timeA, timeB)
			grwg.Add(1)
			go func() { defer grwg.Done(); retc <- api.Reply{Data: nil, Err: errbigdt} }()
		} else {
			log.Printf("3:%v %v", timeA, timeB)
			ar.Query(timeA, timeB, retc, &grwg) //this will fire a new goroutine
		}
	}
	// the last goroutine that will wait for all we invoked and close the chan
done:
	go func(wg *sync.WaitGroup) {
		wg.Wait()   //wait for all the goroutines to finish sending
		close(retc) //close the chan so that range in responsewriter will finish
		log.Printf("closing the chan\n")
	}(&grwg)
	return h, retc

}

func timeToString(a time.Time) string {
	return a.UTC().Format("20060102150405")
}

func handleParams(values url.Values, ar contarchive) (api.HdrReply, chan api.Reply) {
	var (
		grwg sync.WaitGroup
		defh api.HdrReply
	)
	defh.Code = 200
	contid, ok1 := values["continuous"]
	_, ok2 := values["start"]
	_, ok3 := values["end"]
	ip, ok4 := values["remoteaddr"]
	if !ok4 {
		log.Printf("remoteaddr has not been plugged in the url.Values dictionary")
		ip = []string{"IP error"}
	}
	if !ok1 {
		return getTimerange(values, ar, defh)
	}
	retc := make(chan api.Reply)
	creqch, crepch := ar.getContextChans()
	//continuous has to be only by itself or with a start on a request
	if ok3 || len(contid) > 1 {
		grwg.Add(1)
		go func() { defer grwg.Done(); retc <- api.Reply{Data: nil, Err: errbadreq} }()
		goto done
	}
	switch contid[0] {
	case "begin":
		log.Printf("register request handler for cli %s", ip[0])
		arg := contCli{ip: ip[0]}
		creqch <- contCmd{cmd: CONT_ADD, cli: arg}
		rep := <-crepch
		if rep.err == nil {
			log.Printf("register api.Reply handler for cli %+v", rep)
			defh.Extra = rep.id
			//handle the case where the user also has specified a start in here
			if ok2 {
				//we create a string of the current time.
				values["end"] = []string{timeToString(time.Now())}
				return getTimerange(values, ar, defh)
			}
		} else {
			log.Printf("error :%s", rep.err)
			grwg.Add(1)
			go func() { defer grwg.Done(); retc <- api.Reply{Data: nil, Err: rep.err} }()
			goto done
		}
	default:
		log.Printf("will query handler %s for cli %s", contid[0], ip[0])
		arg := contCli{ip: ip[0], id: contid[0]}
		creqch <- contCmd{cmd: CONT_GET, cli: arg}
		rep := <-crepch
		if rep.err == nil {
			log.Printf("sending next id for cli %+v", rep)
			defh.Extra = rep.id
			if !rep.t2pull.IsZero() { //
				ar.Query(rep.t1pull, rep.t2pull, retc, &grwg)
				goto done
			}
		} else {
			log.Printf("error :%s", rep.err)
			grwg.Add(1)
			go func() { defer grwg.Done(); retc <- api.Reply{Data: nil, Err: rep.err} }()
			goto done
		}
	}
done:
	go func(wg *sync.WaitGroup) {
		wg.Wait()   //wait for all the goroutines to finish sending
		close(retc) //close the chan so that range in responsewriter will finish
		log.Printf("closing the chan\n")
	}(&grwg)
	return defh, retc

}

func (fsa fsarchive) Get(values url.Values) (api.HdrReply, chan api.Reply) {
	return handleParams(values, fsa)
}

func (pba pbarchive) Get(values url.Values) (api.HdrReply, chan api.Reply) {
	return handleParams(values, pba)
}

func (jsa jsonarchive) Get(values url.Values) (api.HdrReply, chan api.Reply) {
	return handleParams(values, jsa)
}

func (fss fsarstat) Get(values url.Values) (api.HdrReply, chan api.Reply) {
	return getTimerange(values, fss, api.HdrReply{Code: 200})
}

func (ma fsarchive) getFileIndexRange(ta, tb time.Time) (int, int, error) {
	ef := ma.entryfiles
	if len(ef) == 0 {
		return 0, 0, errempty
	}
	if tb.Before(ef[0].Sdate) || ta.After(ef[len(ef)-1].Sdate.Add(ma.timedelta)) {
		return 0, 0, errdate
	}
	i := sort.Search(len(ef), func(i int) bool {
		return ef[i].Sdate.After(ta.Add(-ma.timedelta - time.Second))
	})
	j := sort.Search(len(ef), func(i int) bool {
		return ef[i].Sdate.After(tb)
	})

	if ma.debug {
		log.Printf("indexes [i:%d j:%d]", i, j)
	}
	return i, j, nil
}

type transformer func([]byte) ([]byte, error)

func newIdentityTransformer() transformer {
	return func(a []byte) ([]byte, error) {
		return a, nil
	}
}

func newProtobufTransformer() transformer {
	return func(a []byte) ([]byte, error) {
		//check if it is a rib
		isrib, _ := ppmrt.IsRib(a)
		if isrib {
			return nil, fmt.Errorf("Protobuf RIB output is not yet supported")
		}

		bb := new(bytes.Buffer)
		pb, err := ppmrt.MrtToBGPCapture(a)
		if err != nil {
			return nil, err
		}
		pbytes, err := proto.Marshal(pb)
		if err != nil {
			return nil, err
		}
		blen := uint32(len(pbytes))
		binary.Write(bb, binary.BigEndian, blen)
		bb.Write(pbytes)
		return bb.Bytes(), nil
	}
}

func newJsonTransformer() transformer {
	return func(a []byte) ([]byte, error) {
		mrth := ppmrt.NewMrtHdrBuf(a)
		bgp4h, err := mrth.Parse()
		if err != nil {
			log.Printf("Failed parsing MRT header:%s", err)
		}
		//check if it is a rib
		isrib, _ := ppmrt.IsRib(a)
		if isrib {
			return nil, fmt.Errorf("JSON RIB output is not yet supported")
		}
		bgph, err := bgp4h.Parse()
		if err != nil {
			log.Printf("Failed parsing BG4MP header:%s", err)
			return nil, err
		}
		bgpup, err := bgph.Parse()
		if err != nil {
			log.Printf("Failed parsing BGP header:%s", err)
			return nil, err
		}
		_, err = bgpup.Parse()
		if err != nil {
			log.Printf("Failed parsing BGP update:%s", err)
			return nil, err
		}
		mbs := &ppmrt.MrtBufferStack{mrth, bgp4h, bgph, bgpup}
		mbsj, err := json.Marshal(mbs)
		mbsj = append(mbsj, []byte("\n")...)
		return []byte(mbsj), nil
	}
}

func transformAndSendBytes(ar fsarchive, ta, tb time.Time, rc chan<- api.Reply, trans transformer) {
	var (
		transdata []byte
		terr      error
	)
	i, j, err := ar.getFileIndexRange(ta, tb)

	if err != nil {
		rc <- api.Reply{nil, err}
		return
	}
	ef := ar.entryfiles

	for k := i; k < j; k++ {
		if ar.debug {
			log.Printf("opening:%s", ef[k].Path)
		}
		file, ferr := os.Open(ef[k].Path)
		if ferr != nil {
			log.Println("failed opening file: ", ef[k].Path, " ", ferr)
			continue
		}
		scanner := util.GetScanner(file)
		startt := time.Now()
		for scanner.Scan() {
			data := scanner.Bytes()

			if len(data) < 4 {
				log.Printf("error in creating MRT header:%s", err)
				rc <- api.Reply{Data: nil, Err: err}
				continue
			}
			msgtime := time.Unix(int64(binary.BigEndian.Uint32(data[:4])), 0)
			if msgtime.After(ta.Add(-time.Second)) && msgtime.Before(tb.Add(time.Second)) {
				//documenation was saying that the Bytes() returnned from a scanner
				//can be overwritten by subsequent calls to Scan().
				//if we don't copy the bytes here, we have an awful race.
				if trans != nil {
					transdata, terr = trans(data)
				} else {
					transdata, terr = data, nil
				}
				//dsp:on a second though this might not end up in a race due to channel block before the next write.
				//cp := make([]byte, len(data))
				//copy(cp, data)
				rc <- api.Reply{Data: transdata, Err: terr}
			}
		}
		if err := scanner.Err(); err != nil && err != io.EOF {
			log.Printf("file scanner error:%s\n", err)
		}
		log.Printf("finished parsing file %s size %d in %s\n", ef[k].Path, ef[k].Sz, time.Since(startt))
		file.Close()
	}

}

func (ma fsarchive) Query(ta, tb time.Time, retc chan api.Reply, wg *sync.WaitGroup) {
	log.Printf("mrt query from %s to %s\n", ta, tb)
	//Always add to the waitgroup before calling the go statement.
	wg.Add(1)
	go func(rc chan<- api.Reply) {
		defer wg.Done()
		it := newIdentityTransformer()
		transformAndSendBytes(ma, ta, tb, rc, it)
		return
	}(retc)
}

func (pba pbarchive) Query(ta, tb time.Time, retc chan api.Reply, wg *sync.WaitGroup) {
	log.Printf("protobuf query from %s to %s\n", ta, tb)
	//Always add to the waitgroup before calling the go statement.
	wg.Add(1)
	go func(rc chan<- api.Reply) {
		defer wg.Done()
		pt := newProtobufTransformer()
		transformAndSendBytes(*pba.fsarchive, ta, tb, rc, pt)
		return
	}(retc)
}

func (jsa jsonarchive) Query(ta, tb time.Time, retc chan api.Reply, wg *sync.WaitGroup) {
	log.Printf("json query from %s to %s\n", ta, tb)
	//Always add to the waitgroup before calling the go statement.
	wg.Add(1)
	go func(rc chan<- api.Reply) {
		defer wg.Done()
		jt := newJsonTransformer()
		transformAndSendBytes(*jsa.fsarchive, ta, tb, rc, jt)
		return
	}(retc)
}

func (fss fsarstat) Query(ta, tb time.Time, retc chan api.Reply, wg *sync.WaitGroup) {
	log.Printf("stat query from %s to %s\n", ta, tb)
	//Always add to the waitgroup before calling the go statement.
	wg.Add(1)
	go func(rc chan<- api.Reply) {
		st := &BgpStats{}
		var (
			lastTime     time.Time
			totreach     int
			totunreach   int
			totnlri      int
			totwithdrawn int
			totdelta     int
		)
		defer wg.Done()
		ma := fss.fsarchive
		i, j, err := ma.getFileIndexRange(ta, tb)

		if err != nil {
			rc <- api.Reply{nil, err}
			return
		}
		ef := ma.entryfiles
		for k := i; k < j; k++ {
			if fss.debug {
				log.Printf("opening:%s", ef[k].Path)
			}
			file, ferr := os.Open(ef[k].Path)
			if ferr != nil {
				log.Println("failed opening file: ", ef[k].Path, " ", ferr)
				continue
			}
			scanner := util.GetScanner(file)
			startt := time.Now()
			if k == i { //only on the first file to be examined
				lastTime = ta //set it to the beginning of interval
			}
			for scanner.Scan() {
				data := scanner.Bytes()

				hdrbuf := ppmrt.NewMrtHdrBuf(data)
				bgp4hbuf, err := hdrbuf.Parse()
				if err != nil {
					log.Printf("error in creating MRT header:%s", err)
					continue
				}
				hdr := hdrbuf.GetHeader()
				msgtime := time.Unix(int64(hdr.Timestamp), 0)
				bgphdrbuf, err := bgp4hbuf.Parse()
				if err != nil {
					log.Printf("error in creating BGP4MP header:%s", err)
					continue
				}
				bgpupbuf, err := bgphdrbuf.Parse()
				if err != nil {
					log.Printf("error in parsing BGP header:%s", err)
					continue
				}
				bgpupbuf.Parse()
				//if err != nil {
				//log.Printf("error in parsing BGP update:%s", err)
				//continue
				//}

				up := bgpupbuf.(pp.BGPUpdater).GetUpdate()
				if msgtime.After(ta.Add(-time.Second)) && msgtime.Before(tb.Add(time.Second)) {
					st.TotalMsgs += 1
					secsfromlast := int(msgtime.Sub(lastTime).Seconds())
					if secsfromlast < 0 {
						log.Printf("Warning! secs from last msg less than 0:%d", secsfromlast)
					} else if secsfromlast == 0 {
						totdelta += 1
						if up.WithdrawnRoutes != nil {
							totwithdrawn += len(up.WithdrawnRoutes.Prefixes)
						}
						if up.AdvertizedRoutes != nil {
							totnlri += len(up.AdvertizedRoutes.Prefixes)
						}
						if up.Attrs != nil {
							for _, att := range up.Attrs.Types {
								if att == pb.BGPUpdate_Attributes_MP_REACH_NLRI {
									totreach += 1
								} else if att == pb.BGPUpdate_Attributes_MP_UNREACH_NLRI {
									totunreach += 1
								}
							}
						}
					} else if secsfromlast > 0 {
						// flush the previous
						st.Withdrawn = append(st.Withdrawn, totwithdrawn)
						st.NLRI = append(st.NLRI, totnlri)
						st.MPReach = append(st.MPReach, totreach)
						st.MPUnreach = append(st.MPUnreach, totunreach)
						st.TotalPerDelta = append(st.TotalPerDelta, totdelta)
						//reset
						totwithdrawn, totnlri, totreach, totunreach, totdelta = 0, 0, 0, 0, 0
						if secsfromlast > 1 {
							for sec := 1; sec < secsfromlast; sec++ {
								//log.Printf("inserting one dummy")
								st.Withdrawn = append(st.Withdrawn, 0)
								st.NLRI = append(st.NLRI, 0)
								st.MPReach = append(st.MPReach, 0)
								st.MPUnreach = append(st.MPUnreach, 0)
								st.TotalPerDelta = append(st.TotalPerDelta, 0)
							}
						}
						totdelta += 1
						if up.WithdrawnRoutes != nil {
							totwithdrawn += len(up.WithdrawnRoutes.Prefixes)
						}
						if up.AdvertizedRoutes != nil {
							totnlri += len(up.AdvertizedRoutes.Prefixes)
						}

						if up.Attrs != nil {
							for _, att := range up.Attrs.Types {
								//log.Println("attribute: ", att)
								if att == pb.BGPUpdate_Attributes_MP_REACH_NLRI {
									totreach += 1
								} else if att == pb.BGPUpdate_Attributes_MP_UNREACH_NLRI {
									totunreach += 1
								}
							}
						}
						lastTime = msgtime
					}
				}
			}
			if err := scanner.Err(); err != nil && err != io.EOF {
				log.Printf("file scanner error:%s\n", err)
			}
			log.Printf("finished parsing file %s size %d in %s\n", ef[k].Path, ef[k].Sz, time.Since(startt))
			file.Close()
		}
		st.StartTime = fmt.Sprintf("%s", ta)
		st.EndTime = fmt.Sprintf("%s", tb)
		st.Delta_sec = 1
		//statstr := fmt.Sprintf("%+v\n", st)
		b, err := json.Marshal(st)
		if err != nil {
			log.Printf("error in json marshal:%s", err)
		}
		rc <- api.Reply{Data: b, Err: nil}
		return
	}(retc)
}

//revisit is run when we need to check for new files that are probably rsynced to the archive.
//it uses some heuristics to ignore directories from routeviews that would contain stuff we have
//already indexed. It is called by rescan.
func (fsa *mrtarchive) revisit(pathname string, f os.FileInfo, err error) error {
	if f == nil {
		return errors.New("fileinfo is nil")
	}

	fname := f.Name()
	ld, derr := fsa.lastDate()
	if derr != nil {
		return derr
	}
	if f.Mode().IsDir() {
		if fsa.debug {
			log.Printf("reexamining dir:%s last archived date is:%v\n", fname, ld)
		}
		ok, yr, mon := isYearMonthDir(path.Base(pathname))
		if ok {
			log.Printf("%s is a year month dir with yr:%v month:%v", fname, yr, mon)
			if yr < ld.Year() {
				if fsa.debug {
					log.Printf("year is less than:%v", ld.Year())
				}
				return filepath.SkipDir
			}
			if mon < int(ld.Month()) && yr <= ld.Year() {
				if fsa.debug {
					log.Printf("month is less than:%v", int(ld.Month()))
				}
				return filepath.SkipDir
			}
			//if here we are in the correct dir as our last scanned year.month
			return nil
		}
	}
	if err != nil {
		return err
	}
	if strings.LastIndex(pathname, fsa.descriminator) == -1 {
		if fsa.debug {
			log.Printf("visit: descriminator:%s not found in path:%s . ignoring\n", fsa.descriminator, pathname)
		}
		return nil
	}
	if f.Mode().IsRegular() {
		//skip temporary files being rsynced that start with .
		if fstr := path.Base(pathname); len(fstr) > 0 && fstr[0] == '.' {
			return nil
		}
		time, errtime := util.GetFirstDate(pathname)
		if errtime != nil {
			if fsa.debug {
				log.Print("GetFirstDate failed on file: ", fname, " that should be in fooHHMM format with error: ", errtime)
			}
			return nil
		}
		if time.After(ld) { // only add files that are later than current lastdate.
			log.Printf("adding file:%s with date:%v to the archive\n", pathname, time)
			fsa.tempentryfiles = append(fsa.tempentryfiles, ArchEntryFile{Path: pathname, Sdate: time, Sz: f.Size()})
		} else {
			//log.Printf("on: %s time:%v not later than last archived time:%v", fname, time, ld)
		}
	}
	return nil
}

func (fsa *mrtarchive) visit(pathname string, f os.FileInfo, err error) error {
	fname := f.Name()
	//log.Print("examining mrt: ", fname)
	if strings.LastIndex(pathname, fsa.descriminator) == -1 {
		if fsa.debug {
			log.Printf("visit: descriminator:%s not found in path:%s . ignoring\n", fsa.descriminator, pathname)
		}
		return nil
	}
	if f.Mode().IsRegular() {
		//skip temporary files being rsynced that start with .
		if fstr := path.Base(pathname); len(fstr) > 0 && fstr[0] == '.' {
			return nil
		}
		time, errtime := util.GetFirstDate(pathname)
		if errtime != nil {
			if fsa.debug {
				log.Print("time.Parse() failed on file: ", fname, " that should be in fooHHMM format with error: ", errtime)
			}
			return nil
		}
		fsa.tempentryfiles = append(fsa.tempentryfiles, ArchEntryFile{Path: pathname, Sdate: time, Sz: f.Size()})
	}
	return nil
}

func NewMRTArchive(path, descr, colname string, ref int, savepath string, debug bool) *mrtarchive {
	return &mrtarchive{fsarchive: NewFsArchive(path, descr, colname, ref, savepath, debug)}
}

func NewFsArchive(path, descr, colname string, ref int, savepath string, debug bool) *fsarchive {
	return &fsarchive{
		rootpathstr:    path,
		entryfiles:     TimeEntrySlice{},
		tempentryfiles: TimeEntrySlice{},
		reqchan:        make(chan string),
		scanning:       false,
		scanwg:         &sync.WaitGroup{},
		scanch:         make(chan struct{}),
		timedelta:      15 * time.Minute,
		descriminator:  descr,
		refreshmin:     ref,
		contctx:        newContCtx(),
		collectorstr:   colname,
		savepath:       savepath,
		debug:          debug,
	}
}

func (fsar *fsarchive) SetTimeDelta(a time.Duration) {
	fsar.timedelta = a
}

func (fsar fsarchive) lastDate() (time.Time, error) {
	if len(fsar.entryfiles) == 0 {
		return time.Now(), errempty
	}
	return fsar.entryfiles[len(fsar.entryfiles)-1].Sdate, nil
}

//trying to see if a dir name is in YYYY.MM form
//returns true, year, month if it is, or false, 0, 0 if not.
//input fname should be a Base dir. meaning it would be good to
//get it from a path.Base() function
func isYearMonthDir(fname string) (res bool, yr int, mon int) {
	var err error
	res = false
	yr = 0
	mon = 0
	isdot := func(r rune) bool {
		if r == '.' {
			return true
		}
		return false
	}
	ind := strings.IndexFunc(fname, isdot)
	//not found or in the form foo.
	if ind == -1 || ind == len(fname) {
		return
	}
	//not YYYY or MM
	if len(fname[:ind]) != 4 || len(fname[ind+1:]) != 2 {
		return
	}
	yr, err = strconv.Atoi(fname[:ind])
	if err != nil {
		return
	}
	mon, err = strconv.Atoi(fname[ind+1:])
	if err != nil {
		return
	}
	if mon < 1 || mon > 12 {
		return
	}
	//the values were found to be valid
	res = true
	return
}

func (fsa fsarchive) printEntries() {
	log.Printf("dumping entries")
	for _, ef := range fsa.entryfiles {
		fmt.Printf("%s %s\n", ef.Path, ef.Sdate)
	}
}

func (fsa *mrtarchive) rescan() {
	fsa.scanning = true
	fsa.tempentryfiles = TimeEntrySlice{}
	filepath.Walk(fsa.rootpathstr, fsa.revisit)
	sort.Sort(fsa.tempentryfiles)
	fsa.mergeTempEntryWithEntryFiles()
}

func (fsa *mrtarchive) scan() {
	fsa.scanning = true
	fsa.tempentryfiles = TimeEntrySlice{}
	filepath.Walk(fsa.rootpathstr, fsa.visit)
	sort.Sort(fsa.tempentryfiles)
	fsa.StoreTempEntryFiles()
}

func (fsa *mrtarchive) Serve(wg, allscanwg *sync.WaitGroup) (reqchan chan<- string) {
	if fsa.reqchan == nil { // we have closed the channel and now called again
		fsa.reqchan = make(chan string)
	}
	tick := time.NewTicker(time.Minute * time.Duration(fsa.refreshmin))
	log.Printf("rescanning every :%v", time.Minute*time.Duration(fsa.refreshmin))
	wg.Add(1)
	go func() {
		fstr := fmt.Sprintf("%s/%s-%s", fsa.savepath, fsa.descriminator, fsa.collectorstr)
		defer wg.Done()
		for {
			select {
			case req := <-fsa.reqchan:
				switch req {
				case "SCAN":
					if fsa.scanning {
						log.Print("fsarchive: already scanning. ignoring command")
					} else { //fire an async goroutine to scan the files and wait for SCANDONE
						log.Printf("fsarchive:%s scanning.", fstr)
						allscanwg.Add(1)
						fsa.scanwg.Add(1)
						fsa.scan()
						fsa.scanning = false
						fsa.scanwg.Done()
						allscanwg.Done()
					}
				case "RESCAN":
					if fsa.scanning {
						log.Print("fsarchive: already scanning. ignoring command")
					} else { //fire an async goroutine to scan the files and wait for SCANDONE
						log.Printf("fsarchive:%s rescanning.", fstr)
						fsa.rescan()
						errg := fsa.Save(fstr)
						if errg != nil {
							log.Println(errg)
						} else {
							log.Printf("succesfully rewrote serialized file:%s for archive:%s", fstr, fsa.descriminator)
						}
						fsa.scanning = false
					}
				case "DUMPENTRIES":
					if fsa.scanning {
						log.Printf("fsar:%s warning. scanning in progress", fsa.descriminator)
					}
					fsa.printEntries()
				case "STOP":
					log.Printf("fsar:%s stopping", fsa.descriminator)
					fsa.scanwg.Wait()
					tick.Stop()
					fsa.reqchan = nil //no more stuff from this channel
					return
				}
			case <-tick.C:
				log.Printf("rescanning")
				if fsa.scanning {
					log.Print("fsarchive: already scanning. ignoring command")
				} else { //fire an async goroutine to scan the files and wait for SCANDONE
					log.Printf("fsarchive:%s rescanning.", fstr)
					fsa.rescan()
					//rewrite the file
					errg := fsa.Save(fstr)
					if errg != nil {
						log.Println(errg)
					} else {
						log.Printf("succesfully rewrote serialized file:%s for archive:%s", fstr, fsa.descriminator)
					}
					fsa.scanning = false
				}
			}
		}
	}()
	//firing continuous cli pull context server
	log.Printf("firing continuous pull server")
	fsa.contctx.Serve()
	return fsa.reqchan
}
