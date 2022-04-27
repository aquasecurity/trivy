package rpmdb

import (
	"bytes"
	"encoding/binary"
	"log"
)

func Htonl(val int32) int32 {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, val); err != nil {
		log.Println(err)
		return 0
	}

	if err := binary.Read(buf, binary.BigEndian, &val); err != nil {
		log.Println(err)
		return 0
	}
	return val
}

func HtonlU(val uint32) uint32 {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, val); err != nil {
		log.Println(err)
		return 0
	}

	if err := binary.Read(buf, binary.BigEndian, &val); err != nil {
		log.Println(err)
		return 0
	}
	return val
}
