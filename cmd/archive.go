package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	ba "github.com/CSUNetSec/bgparchive"
	api "github.com/CSUNetSec/bgparchive/api"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	flag_refresh_minutes int
	flag_descpaths       descpaths
	flag_basepath        string
	flag_savepath        string
	flag_debug           bool
	flag_conffile        string
	flag_port            int
)

type descpath struct {
	Desc          string
	Path          string
	Delta_minutes int
	Basepath      string
	Collector     string
}

type descpaths []descpath

func (d *descpaths) String() string {
	var ret []string
	for _, dp := range *d {
		ret = append(ret, fmt.Sprintf("[Desc:%s->path:%s delta:%d basepath:%s collector:%s] ", dp.Desc, dp.Path, dp.Delta_minutes, dp.Basepath, dp.Collector))
	}
	return strings.Join(ret, "")
}

func (d *descpaths) Set(val string) error {
	strs := strings.Split(val, ",")
	for _, str := range strs {
		set := strings.Split(str, ":")
		if len(set) != 5 {
			return errors.New("syntax: fspath2:descriminator1:path1:delta_minutes1:collector1, fspath2:descriminator2:path2:delta_minutes2:collector2, ...")
		}
		dm, dmerr := strconv.Atoi(set[3])
		if dmerr != nil {
			return dmerr
		}
		*d = append(*d, descpath{Basepath: set[0], Desc: set[1], Path: set[2], Delta_minutes: dm, Collector: set[4]})
	}
	return nil
}

func init() {
	flag.IntVar(&flag_refresh_minutes, "refresh-minutes", 5, "rescan db every x minutes")
	flag.Var(&flag_descpaths, "descriminator-paths", "comma seperated list of fsbasepath:descriminator:urlpath:delta_minutes:collectorname quints")
	flag.StringVar(&flag_savepath, "savepath", ".", "directory to save the binary archive index files")
	flag.StringVar(&flag_conffile, "conf", "", "configuration file")
	flag.BoolVar(&flag_debug, "debug", false, "turn on debugging")
	flag.IntVar(&flag_port, "port", 80, "default port for the HTTP server to bind to")
}

func main() {
	flag.Parse()
	if flag_conffile != "" { //the configuration file will overwrite any config from the command line
		file, err := os.Open(flag_conffile)
		if err != nil {
			log.Fatal(err)
		}
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&flag_descpaths)
		if err != nil {
			log.Fatal(err)
		}
		file.Close()
	}
	var ars ba.MrtArchives
	if len(flag_descpaths) == 0 {
		log.Fatal("not descriminators and paths specified")
	}

	api := api.NewAPI()
	servewg := &sync.WaitGroup{}
	allscanwg := &sync.WaitGroup{}
	hmsg := new(ba.HelpMsg)
	for i, v := range flag_descpaths {
		ars = append(ars, ba.NewMRTArchive(v.Basepath, v.Desc, v.Collector, flag_refresh_minutes, flag_savepath, flag_debug))
		ars[i].SetTimeDelta(time.Duration(v.Delta_minutes) * time.Minute)
		statar := ba.NewFsarstat(ars[i].GetFsArchive())
		fsc := ba.NewFsarconf(ars[i].GetFsArchive())
		pbar := ba.NewPbArchive(ars[i].GetFsArchive())
		jsar := ba.NewJsonArchive(ars[i].GetFsArchive())
		api.AddResource(ars[i], fmt.Sprintf("/archive/mrt/%s%s", v.Collector, v.Path))
		api.AddResource(pbar, fmt.Sprintf("/archive/pb/%s%s", v.Collector, v.Path))
		api.AddResource(jsar, fmt.Sprintf("/archive/json/%s%s", v.Collector, v.Path))
		api.AddResource(fsc, fmt.Sprintf("/archive/mrt/%s%s/conf", v.Collector, v.Path))
		api.AddResource(statar, fmt.Sprintf("/archive/mrt/%s%s/stats", v.Collector, v.Path))
		mrtreqc := ars[i].Serve(servewg, allscanwg)
		errg := ars[i].Load(fmt.Sprintf("%s/%s-%s", flag_savepath, v.Desc, v.Collector))
		if errg != nil {
			log.Printf("failed to find serialized file. Scanning")
			mrtreqc <- "SCAN"
			//log.Printf("Entryfiles are:%s", ars[i].tempentryfiles)
			allscanwg.Wait()
			errg = ars[i].Save(fmt.Sprintf("%s/%s-%s", flag_savepath, v.Desc, v.Collector))
			if errg != nil {
				log.Println(errg)
			} else {
				log.Printf("created serialized file for archive:%v", v)
			}
		} else {
			//log.Printf("Found serialized file for archive:%s. entryfiles:%s", v, ars[i].entryfiles)
			log.Printf("Found serialized file for archive:%v.", v)
			ars[i].SetEntryFilesToTemp()
		}
		hmsg.AddArchive(fsc)
	}
	allscanwg.Wait()
	//the global help message
	api.AddResource(hmsg, "/archive/help")
	api.Start(flag_port)
	for _, v := range ars {
		rc := v.GetReqChan()
		close(rc)
	}
	servewg.Wait()
	log.Print("all fsarchives stopped. exiting")
}
