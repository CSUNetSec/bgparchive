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
	"time"
)

const (
	DEFAULT_RATE = 0.1
)

var (
	output_name string
	print_tes   bool
	sample_rate float64
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
	flag.StringVar(&output_name, "outfile", "", "name of the generated index file")
	flag.StringVar(&output_name, "o", "", "")
	flag.Float64Var(&sample_rate, "rate", DEFAULT_RATE, "sample rate used")
	flag.Float64Var(&sample_rate, "r", DEFAULT_RATE, "")
	flag.BoolVar(&print_tes, "print", false, "Do not create the index file, print the TES file to standard output instead")
	flag.BoolVar(&print_tes, "p", false, "")
}

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) != 1 {
		usage()
		return
	}

	entries := bgp.TimeEntrySlice{}
	err := (&entries).FromGobFile(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}
	if print_tes {
		for _, ent := range entries {
			fmt.Printf("%s\n", ent)
		}
		return
	}

	if output_name == "" {
		output_name = args[0] + "-index"
	}
	for enct, _ := range entries {
		entryfile, err := os.Open(entries[enct].Path)
		if err != nil {
			fmt.Printf("Error opening entry.Path: %s\n", entries[enct].Path)
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

	}
	err = entries.ToGobFile(output_name)
	if err != nil {
		fmt.Printf("Failed to regob\n")
	}
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
	fmt.Println("indextool: writes an indexed version of a TimeEntrySlice into a specified file.")
	fmt.Println("usage: indextool [outfile|print|rate] tes-file")
	fmt.Println("See indextool -h for a list of options.")
}
