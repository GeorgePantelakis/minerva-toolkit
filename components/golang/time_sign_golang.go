package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
}

func main() {
	var in_file_name string
	var out_file_name string
	var time_file_name string
	var key_file_name string
	var data_size int

	var time_before uint64 = 0
	var time_after uint64 = 0
	var time_diff uint64 = 0

	flag.StringVar(&in_file_name, "i", "", "File with data to sign")
	flag.StringVar(&out_file_name, "o", "", "File to write the signatures")
	flag.StringVar(&time_file_name, "t", "", "File to write the time to sign the hashes")
	flag.StringVar(&key_file_name, "k", "", "File with the private key in PEM format")
	flag.IntVar(&data_size, "s", 0, "Size of each block of data to sign")
	flag.Parse()

	if len(in_file_name) == 0 || len(out_file_name) == 0 ||
		len(time_file_name) == 0 || len(key_file_name) == 0 {
		fmt.Fprintf(os.Stderr, "Missing parameters!\n")
		os.Exit(1)
	}

	in_file, err := os.Open(in_file_name)
	if err != nil {
		panic(err)
	}
	defer in_file.Close()

	in_file_reader := bufio.NewReader(in_file)

	out_file, err := os.Create(out_file_name)
	if err != nil {
		panic(err)
	}

	time_file, err := os.Create(time_file_name)
	if err != nil {
		panic(err)
	}

	key_file_cont, err := os.ReadFile(key_file_name)
	if err != nil {
		panic(err)
	}

	key_block, _ := pem.Decode(key_file_cont)
	privateKeyRaw, err := x509.ParsePKCS8PrivateKey(key_block.Bytes)
	if err != nil {
		panic(err)
	}
	privateKey := privateKeyRaw.(*ecdsa.PrivateKey)

	for {
		data := make([]byte, data_size)

		_, err := in_file_reader.Read(data)
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Println(err)
			break
		}

		if err != nil {
			// end of file
			break
		}

		if len(data) != data_size {
			fmt.Fprintf(os.Stderr, "read less data than expected (truncated file?)\n")
			fmt.Fprintf(os.Stderr, "read %d bytes instead of %d\n", len(data), data_size)
			os.Exit(1)
		}

		time_before = uint64(time.Now().Nanosecond())
		sig, err := ecdsa.SignASN1(rand.Reader, privateKey, data)
		if err != nil {
			panic(err)
		}
		time_after = uint64(time.Now().Nanosecond())

		err = binary.Write(out_file, nativeEndian, sig)
		if err != nil {
			fmt.Println("Error on writing sigs to file: ", err)
			break
		}

		time_diff = time_after - time_before
		err = binary.Write(time_file, nativeEndian, time_diff)
		if err != nil {
			fmt.Println("Error on writing times to file: ", err)
			break
		}
	}
}
