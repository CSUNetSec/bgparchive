package main

// indextool
// usage: indextool -f file
// Given an input file, prints the ArchFileEntries within it

import (
	"bufio"
	"compress/bzip2"
	"encoding/binary"
	"flag"
	"fmt"
	bgp "github.com/CSUNetSec/bgparchive"
	pbmrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	DEFAULT_RATE = 0.1
)

var (
	output_suffix string
	print_tes     bool
	sample_rate   float64
	new_dir       string
)

func GetScanner(file *os.File) (scanner *bufio.Scanner) {
	fname := file.Name()
	fext := filepath.Ext(fname)
	if fext == ".bz2" {
		//log.Printf("bunzip2 file: %s. opening decompression stream", fname)
		bzreader := bzip2.NewReader(file)
		scanner = bufio.NewScanner(bzreader)
		scanner.Split(pbmrt.SplitMrt)
	} else {
		//log.Printf("no extension on file: %s. opening normally", fname)
		scanner = bufio.NewScanner(file)
		scanner.Split(pbmrt.SplitMrt)
	}
	return
}

func init() {
	flag.StringVar(&output_suffix, "outsuffix", "", "suffix of the generated index file")
	flag.StringVar(&output_suffix, "o", "", "")
	flag.Float64Var(&sample_rate, "rate", DEFAULT_RATE, "sample rate used")
	flag.Float64Var(&sample_rate, "r", DEFAULT_RATE, "")
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
			go createIndexedTESFile(tesName, &wg)
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

func createIndexedTESFile(tesName string, wg *sync.WaitGroup) {
	defer wg.Done()
	entries := bgp.TimeEntrySlice{}
	err := (&entries).FromGobFile(tesName)
	if err != nil {
		fmt.Printf("Error opening indexfile: %s\n", tesName)
		return
	}
	output_name := tesName + "." + output_suffix
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
		m := Generate_Index(GetScanner(entryfile), entries[enct].Sz, sample_rate, getTimestampFromMRT)
		entries[enct].Offsets = make([]bgp.EntryOffset, len(m))
		for ct, offset := range m {
			if offset != nil {
				fmt.Printf("Adding offset %d: %v\n", ct, offset)
				entries[enct].Offsets[ct] = bgp.EntryOffset{offset.Value.(time.Time), offset.Off}
			} else {
				fmt.Printf("Null offset, should not have happened.\n")
			}
		}
		entryfile.Close()
	}
	err = entries.ToGobFile(output_name)
	if err != nil {
		fmt.Printf("Error regobing TES: %s\n", tesName)
	}
	return
}

func getTimestampFromMRT(data []byte) (interface{}, error) {
	if len(data) < pbmrt.MRT_HEADER_LEN {
		return nil, fmt.Errorf("Data less than header length.\n")
	}
	unix_t := binary.BigEndian.Uint32(data[:4])
	return time.Unix(int64(unix_t), 0), nil
}

type ItemOffset struct {
	Value interface{}
	Off   int64
}

func NewItemOffset(val interface{}, pos int64) *ItemOffset {
	return &ItemOffset{val, pos}
}

// Generates indexes based on the file size and sample rate
// The scanner must be initialized and Split to parse messages
// before given to this function
func Generate_Index(scanner *bufio.Scanner, fsize int64, sample_rate float64, translate func([]byte) (interface{}, error)) []*ItemOffset {

	if sample_rate < 0.0 || sample_rate > 1.0 {
		sample_rate = DEFAULT_RATE
	}

	indices := make([]*ItemOffset, int(1/sample_rate))
	sample_dist := sample_rate * float64(fsize)
	index_ct := 0
	var actual_pos int64 = 0
	for scanner.Scan() {
		data := scanner.Bytes()
		actual_pos += int64(len(data))
		if float64(actual_pos) > float64(index_ct)*sample_dist && index_ct < len(indices) {
			td, err := translate(data)
			if err == nil {
				indices[index_ct] = NewItemOffset(td, actual_pos)
				index_ct++
			}
		}
	}

	return indices
}

func usage() {
	fmt.Println("indextool: writes an indexed version of a TimeEntrySlice into a specified file,\nprints an index file, or rewrites the dir of TimeEntrySlices.")
	fmt.Println("usage: indextool [flags] original-tes-file")
	fmt.Println("See indextool -h for a list of flags.")
}
