package util

import (
	"bufio"
	"compress/bzip2"
	"encoding/binary"
	"fmt"
	ppmrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	TYPICAL_BZIP2_COMP_RATIO = 8
	DEFAULT_RATE             = 0.1
)

type ItemOffset struct {
	Value interface{}
	Off   int64
}

func NewItemOffset(val interface{}, pos int64) ItemOffset {
	return ItemOffset{val, pos}
}

//returns an underlying bufio.Scanner if file is bz2 or plan
//and sets the Split function to SplitMrt from protoparse.
func GetScanner(file *os.File) (scanner *bufio.Scanner) {
	fname := file.Name()
	fext := filepath.Ext(fname)
	if fext == ".bz2" {
		//log.Printf("bunzip2 file: %s. opening decompression stream", fname)
		bzreader := bzip2.NewReader(file)
		scanner = bufio.NewScanner(bzreader)
		scanner.Split(ppmrt.SplitMrt)
	} else {
		//log.Printf("no extension on file: %s. opening normally", fname)
		scanner = bufio.NewScanner(file)
		scanner.Split(ppmrt.SplitMrt)
	}
	scanbuffer := make([]byte, 2<<24) //an internal buffer for the large tokens (1M)
	scanner.Buffer(scanbuffer, cap(scanbuffer))
	return
}

// Generates indexes based on the file size and sample rate
// The scanner must be initialized and Split to parse messages
// before given to this function
func GenerateIndexes(file *os.File, sample_rate float64, translate func([]byte) (interface{}, error)) []ItemOffset {
	var (
		compratio int
	)
	if sample_rate < 0.0001 || sample_rate > 1.0 { //protect ourselves from a huge allocation
		sample_rate = DEFAULT_RATE
	}
	scanner := GetScanner(file)
	fname := file.Name()
	fext := filepath.Ext(fname)
	if fext == ".bz2" {
		compratio = TYPICAL_BZIP2_COMP_RATIO
	} else {
		compratio = 1
	}
	fstat, err := file.Stat()
	if err != nil {
		return nil
	}
	fsize := fstat.Size()
	indices := []ItemOffset{}                                             //create the slice dynamically to only populate offsets that exist.
	sample_dist := int(sample_rate * float64(fsize) * float64(compratio)) // this is an estimate on how
	index_ct := 0
	var actual_pos int64 = 0
	for scanner.Scan() {
		data := scanner.Bytes()
		if actual_pos >= int64(index_ct*sample_dist) {
			td, err := translate(data)
			if err == nil {
				indices = append(indices, NewItemOffset(td, actual_pos))
				index_ct++
			} else {
				log.Printf("Encounter error %s on file %s", err, fname)
			}
		}
		actual_pos += int64(len(data))
	}
	if scerr := scanner.Err(); scerr != nil {
		if scerr == bufio.ErrTooLong { //could be a RIB
			log.Printf("detected RIB on file:%s", file)
			var (
				nb      int
				errread error
			)
			hdbuf := make([]byte, ppmrt.MRT_HEADER_LEN)
			nb, errread = file.Read(hdbuf)
			if nb != ppmrt.MRT_HEADER_LEN || errread != nil {
				log.Printf("RIB file read error. less bytes or %s", errread)
				return indices
			}
			t, _ := GetTimestampFromMRT(hdbuf) // i checked for that err cond just above
			// since a rib in instaneous, create only one index at the start
			indices = append(indices, NewItemOffset(t, 0))
		} else {
			log.Printf("GenerateIndexes scanner error:%s file:%s", scerr, file)
		}
	}
	return indices
}

func GetTimestampFromMRT(data []byte) (interface{}, error) {
	if len(data) < ppmrt.MRT_HEADER_LEN {
		return nil, fmt.Errorf("Data less than header length.\n")
	}
	unix_t := binary.BigEndian.Uint32(data[:4])
	return time.Unix(int64(unix_t), 0), nil
}

func GetFirstDateAndOffsets(fname string) (t time.Time, offs []ItemOffset, err error) {
	file, err := os.Open(fname)
	if err != nil {
		return
	}
	defer file.Close()
	offs = GenerateIndexes(file, 0.1, GetTimestampFromMRT)
	if len(offs) == 0 {
		err = fmt.Errorf("no indexes could be generated for file:%s", fname)
		return
	}
	t = offs[0].Value.(time.Time)
	//log.Printf("getFirstDate got header with time:%v", t)
	return
}
