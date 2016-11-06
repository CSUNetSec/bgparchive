package main

//TODO Change the name of this file, it's terrible

import (
	bgp "bgparchive"
	"encoding/gob"
	"flag"
	"fmt"
	"os"
)

func main() {
	fileName := flag.String("f", "default", "-f the file to parse/index")
	flag.Parse()

	fmt.Println(*fileName)

	f, ferr := os.Open(*fileName)
	if ferr != nil {
		fmt.Println(ferr)
		return
	}

	dec := gob.NewDecoder(f)
	fileEntries := make([]bgp.ArchEntryFile, 10)
	err := dec.Decode(&fileEntries)

	if err != nil {
		fmt.Println(err)
	}
	index := 0
	for _, file := range fileEntries {
		printEntry(file)
		index++
	}
	fmt.Printf("\nNumber of entries: %d\n", index)

}

func printEntry(file bgp.ArchEntryFile) {
	fmt.Printf("%s %s %d(bytes)\n", file.Path, file.Sdate.String(), file.Sz)
}
