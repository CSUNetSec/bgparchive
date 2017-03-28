package util

import (
	"bufio"
	"compress/bzip2"
	"context"
	"encoding/binary"
	"fmt"
	ppmrt "github.com/CSUNetSec/protoparse/protocol/mrt"
	"log"
	"os"
	"path/filepath"
	"time"
)

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

func GetTimestampFromMRT(data []byte) (t time.Time, err error) {
	if len(data) < ppmrt.MRT_HEADER_LEN {
		err = fmt.Errorf("Data less than header length.\n")
	} else {
		unix_t := binary.BigEndian.Uint32(data[:4])
		t = time.Unix(int64(unix_t), 0)
	}
	return
}

func GetFirstDate(fname string) (t time.Time, err error) {
	file, err := os.Open(fname)
	if err != nil {
		return
	}
	defer file.Close()
	hdbuf := make([]byte, ppmrt.MRT_HEADER_LEN)
	nb, errread := file.Read(hdbuf)
	if nb != ppmrt.MRT_HEADER_LEN || errread != nil {
		log.Printf("GetFirstDate read error on:%s. Read %d bytes or error:%s", fname, nb, errread)
	}
	return GetTimestampFromMRT(hdbuf)
}

// Non-blocking context closed function
// Just a simple function for some repeated code
// Returns true if the context has been closed, such as with a cancel func
func NBContextClosed(ctx context.Context) bool {
	closed := false
	select {
	case <-ctx.Done():
		closed = true
	default:
		//Empty default to disable blocking
	}
	return closed
}
