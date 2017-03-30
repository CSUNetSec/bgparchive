package main

// indextool
// usage: indextool -f file
// Given an input file, prints the ArchFileEntries within it

import (
	"flag"
	"fmt"
	bgp "github.com/CSUNetSec/bgparchive"
	util "github.com/CSUNetSec/bgparchive/util"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	output_suffix  string
	print_tes      bool
	sample_rate    float64
	new_dir        string
	remove_indexes bool
)

const (
	DEFAULT_SAMPLING_RATE = 0.1
)

func init() {
	flag.StringVar(&output_suffix, "outsuffix", "", "suffix of the generated index file")
	flag.StringVar(&output_suffix, "o", "", "")
	flag.Float64Var(&sample_rate, "sample", DEFAULT_SAMPLING_RATE, "sample rate used")
	flag.Float64Var(&sample_rate, "s", DEFAULT_SAMPLING_RATE, "")
	flag.BoolVar(&remove_indexes, "r", false, "remove indexes from tes file")
	flag.BoolVar(&print_tes, "print", false, "Do not create the index file, print the TES file to standard output instead")
	flag.BoolVar(&print_tes, "p", false, "")
	flag.StringVar(&new_dir, "dir", "", "rewrit dir of the files referenced in the index. Must be the same across all entries. format is s:olddir:newdir")
}

func main() {
	flag.Parse()
	args := flag.Args()
	var (
		sf  []string
		suf string
	)

	if len(args) < 1 {
		usage()
		return
	}
	ff := func(r rune) bool {
		return r == ':'
	}
	if print_tes {
		for _, tesName := range args {
			fmt.Printf("------ %s ------\n", tesName)
			err := printTes(tesName)
			if err != nil {
				fmt.Printf("Print error: %v\n", err)
			}
			fmt.Printf("\n")
		}
	} else if new_dir != "" {
		fmt.Printf("detecting base path in existing indexfiles\n")
		if sf = strings.FieldsFunc(new_dir, ff); new_dir[0] != 's' && len(sf) != 3 {
			fmt.Printf("error: malformed sed rewrite string")
			return
		}
		for _, ifile := range args {
			err := rewriteDir(ifile, sf[1], sf[2])
			if err != nil {
				fmt.Printf("error:%s", err)
				return
			}
			if output_suffix == "" {
				suf = "newdir"
			} else {
				suf = output_suffix
			}
			fmt.Printf("rewrote %s to %s in file %s\n", sf[1], sf[2], ifile+"."+suf)
		}
	} else {
		var wg sync.WaitGroup

		for _, tesName := range args {
			wg.Add(1)
			if remove_indexes {
				go removeIndexes(tesName, &wg)
			} else {
				go createIndexedTESFile(tesName, &wg)
			}
		}
		wg.Wait()
	}

}

func rewriteDir(ifile, from, to string) error {
	var (
		output_name string
	)
	entries := bgp.TimeEntrySlice{}
	err := (&entries).FromGobFile(ifile)
	if err != nil {
		return fmt.Errorf("Error opening index file: %s\n", ifile)
	}
	if output_suffix != "" {
		output_name = ifile + "." + output_suffix
	} else {
		output_name = ifile + ".newdir"
	}
	for i, ef := range entries {
		if !strings.Contains(ef.Path, from) {
			return fmt.Errorf("from argument string:%s is not the contained in the detected dir:%s\n", from, ef.Path)
		}
		entries[i].Path = strings.Replace(ef.Path, from, to, 1) // we run it as s/a/b not s/a/b/g
	}
	err = entries.ToGobFile(output_name)
	if err != nil {
		fmt.Printf("Error regobing TES: %s\n", output_name)
	}

	return nil
}

func printTes(tesName string) error {
	entries := bgp.TimeEntrySlice{}
	err := (&entries).FromGobFile(tesName)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		fmt.Printf("%s\n", ent)
	}
	return nil
}

func removeIndexes(tesName string, wg *sync.WaitGroup) {
	defer wg.Done()
	entries := bgp.TimeEntrySlice{}
	err := (&entries).FromGobFile(tesName)
	if err != nil {
		fmt.Printf("Error opening indexfile: %s\n", tesName)
		return
	}
	suf := output_suffix
	if suf == "" {
		suf = "plain"
	}
	output_name := tesName + "." + suf
	if _, err := os.Stat(output_name); !os.IsNotExist(err) {
		fmt.Printf("Error: destination file:%s already exists\n", output_name)
		return
	}
	for enct, _ := range entries {
		entryfile, err := os.Open(entries[enct].Path)
		if err != nil {
			fmt.Printf("Error opening ArchEntryFile: %s\n", entries[enct].Path)
			return
		}
		entries[enct].Offsets = nil
		fmt.Printf("Removed offsets for file:%s\n", entries[enct].Path)
		entryfile.Close()
	}
	err = entries.ToGobFile(output_name)
	if err != nil {
		fmt.Printf("Error regobing TES: %s\n", tesName)
	}
	return

}

func createIndexedTESFile(tesName string, wg *sync.WaitGroup) {
	defer wg.Done()
	entries := bgp.TimeEntrySlice{}
	err := (&entries).FromGobFile(tesName)
	if err != nil {
		fmt.Printf("Error opening indexfile: %s\n", tesName)
		return
	}
	suf := output_suffix
	if suf == "" {
		suf = "indexed"
	}
	output_name := tesName + "." + suf
	if _, err := os.Stat(output_name); !os.IsNotExist(err) {
		fmt.Printf("Error: destination file:%s already exists\n", output_name)
		return
	}
	for enct, _ := range entries {
		entryfile, err := os.Open(entries[enct].Path)
		if err != nil {
			fmt.Printf("Error opening ArchEntryFile: %s\n", entries[enct].Path)
			return
		}
		m := util.GenerateIndexes(entryfile, sample_rate, util.GetTimestampFromMRT)
		entries[enct].Offsets = make([]bgp.EntryOffset, len(m))
		for ct, offset := range m {
			if &offset != nil {
				entries[enct].Offsets[ct] = bgp.EntryOffset{offset.Value.(time.Time), offset.Off}
			} else {
				fmt.Printf("Null offset, should not have happened.\n")
			}
		}
		fmt.Printf("Added %d offsets for file:%s\n", len(entries[enct].Offsets), entries[enct].Path)
		entryfile.Close()
	}
	err = entries.ToGobFile(output_name)
	if err != nil {
		fmt.Printf("Error regobing TES: %s\n", tesName)
	}
	return
}

func usage() {
	fmt.Println("indextool: writes an indexed version of a TimeEntrySlice into a specified file,\nprints an index file, or rewrites the dir of TimeEntrySlices.")
	fmt.Println("usage: indextool [flags] original-tes-file")
	fmt.Println("See indextool -h for a list of flags.")
}
