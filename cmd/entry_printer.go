package main

import (
	bgp "bgparchive"
	"flag"
	"fmt"
)

func main() {
	fileName := flag.String("f", "default", "-f the file to parse/index")
	flag.Parse()

	fmt.Println(*fileName)

	entries := new(bgp.TimeEntrySlice)
	err := entries.FromGobFile(*fileName)

	if err != nil {
		fmt.Println(err)
		return
	}
	i := 0
	for _, entry := range *entries {
		printEntry(entry)
		i++
	}
	fmt.Printf("\nNumber of entries: %d\n", i)

}

func printEntry(file bgp.ArchEntryFile) {
	fmt.Printf("%s %s %d(bytes)\n", file.Path, file.Sdate.String(), file.Sz)
}
