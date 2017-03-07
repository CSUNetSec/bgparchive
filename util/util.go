package util

import (
	"bufio"
	"compress/bzip2"
	"encoding/binary"
	"errors"
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

func NewItemOffset(val interface{}, pos int64) *ItemOffset {
	return &ItemOffset{val, pos}
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
func Generate_Index(file *os.File, sample_rate float64, translate func([]byte) (interface{}, error)) []*ItemOffset {
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
	indices := []*ItemOffset{}                                       //create the slice dynamically to only populate offsets that exist.
	sample_dist := sample_rate * float64(fsize) * float64(compratio) // this is an estimate on how
	index_ct := 0
	var actual_pos int64 = 0
	for scanner.Scan() {
		data := scanner.Bytes()
		actual_pos += int64(len(data))
		if float64(actual_pos) >= float64(index_ct)*sample_dist {
			td, err := translate(data)
			if err == nil {
				indices = append(indices, NewItemOffset(td, actual_pos))
				index_ct++
			} else {
				log.Printf("Encounter error %s on file %s", err, fname)
			}
		}
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

func GetFirstDate(fname string) (t time.Time, err error) {
	file, err := os.Open(fname)
	if err != nil {
		log.Println("getFirstDate failed opening file: ", fname, " ", err)
		return
	}
	defer file.Close()
	scanner := GetScanner(file)
	scanner.Scan()
	err = scanner.Err()
	if err != nil {
		if err == bufio.ErrTooLong { //could be a RIB
			var (
				nb      int
				errread error
			)
			hdbuf := make([]byte, ppmrt.MRT_HEADER_LEN)
			nb, errread = file.Read(hdbuf)
			if nb != ppmrt.MRT_HEADER_LEN || errread != nil {
				err = fmt.Errorf("RIB file read error. less bytes or %s", errread)
				return
			}
			hdrbuf := ppmrt.NewMrtHdrBuf(hdbuf)
			_, err = hdrbuf.Parse()
			if err != nil {
				log.Printf("getFirstDate error in creating MRT header:%s", err)
				return
			}
			hdr := hdrbuf.GetHeader()
			t = time.Unix(int64(hdr.Timestamp), 0)
			//log.Printf("getFirstDate got header with time:%v", t)
			return
		}
		log.Printf("getFirstDate scanner error:%s", err)
		return
	}
	data := scanner.Bytes()
	if len(data) < ppmrt.MRT_HEADER_LEN {
		log.Printf("getFirstDate on %s MRT scanner returned less bytes (%d) than the minimum header", fname, len(data))
		return time.Now(), errors.New(fmt.Sprintf("too few bytes read from mrtfile:%s", fname))
	}

	hdrbuf := ppmrt.NewMrtHdrBuf(data)
	_, err = hdrbuf.Parse()
	if err != nil {
		log.Printf("getFirstDate error in creating MRT header:%s", err)
		return
	}
	hdr := hdrbuf.GetHeader()
	t = time.Unix(int64(hdr.Timestamp), 0)
	//log.Printf("getFirstDate got header with time:%v", t)
	return
}
