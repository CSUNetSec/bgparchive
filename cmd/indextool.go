package main

// indextool
// usage: indextool -f file
// Given an input file, prints the ArchFileEntries within it
// TODO Add the ability to print byte offset of each entry

import (
	"flag"
	"fmt"
	bgp "github.com/CSUNetSec/bgparchive"
)

func main() {

	fileName := flag.String("f", "default", "-f the file to parse/index")
	flag.Parse()

	//Non-flag arguments
	if len(flag.Args()) != 0 {
		usage()
		return
	}

	fmt.Println(*fileName)

	entries := new(bgp.TimeEntrySlice)
	err := entries.FromGobFile(*fileName)

	if err != nil {
		fmt.Println(err)
		return
	}
	for _, entry := range *entries {
		fmt.Printf("%s\n", entry)
	}
	fmt.Printf("\nNumber of entries: %d\n", len(*entries))

}

func usage() {
	fmt.Println("indextool prints a list of ArchFileEntries in a given input file.")
	fmt.Println("usage: indextool -f file")

}
