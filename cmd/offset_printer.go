package main

//TODO Change the name of this file, it's terrible

import (
	bgp "bgparchive"
	"encoding/gob"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	fileName := flag.String("-f", "default", "-f the file to parse/index")
	flag.Parse()

	f, ferr := os.Open(*fileName)

	if ferr != nil {
		fmt.Println(err)
		return
	}

	decoder := gob.NewDecoder(f)
	var currEntry bgp.ArchEntryFile
	var startTime time.Time
	first := true
	for decoder.Decode(&currEntry) != nil {
		if first {
			first = false
			startTime = currEnty.Sdate
		}
		pos, serr := f.Seek(0, 1) // Should grab the current position of the file
		if serr != nil {
			fmt.Println(err)
			return
		}
		printEntry(currEntry, pos, currEntry.Sdate.Sub(startTime))
	}
}

func printEntry(file bgp.ArchEntryFile, pos int64, timeOff time.Time) {
	fmt.Println(file.String + " : " + pos + " : " + timeOff)
}
