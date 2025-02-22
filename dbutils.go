package traefik_plugin_geoblock

import (
	"encoding/binary"
	"fmt"
	"os"
)

type DBVersion struct {
	Type         byte
	ColumnWidth4 byte
	Year         byte
	Month        byte
	Day          byte
	ProductCode  byte
	LicenseCode  byte
	DatabaseSize byte
	IPCount4     uint32
	IPBase4      uint32
	IPCount6     uint32
	IPBase6      uint32
	IndexBase4   uint32
	IndexBase6   uint32
}

func (v DBVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Year, v.Month, v.Day)
}

// GetDatabaseVersion reads the version information from an IP2Location database file.
// It returns the version information or an error if the version cannot be read.
func GetDatabaseVersion(filepath string) (*DBVersion, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database file: %w", err)
	}
	defer file.Close()

	// Read first 512 bytes of header
	headerBytes := make([]byte, 512)
	n, err := file.Read(headerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read header bytes: %w", err)
	}
	if n != 512 {
		return nil, fmt.Errorf("incomplete header read: got %d bytes, expected 512", n)
	}

	version := &DBVersion{
		Type:         headerBytes[0] - 1,
		ColumnWidth4: headerBytes[1] * 4,
		Year:         headerBytes[2],
		Month:        headerBytes[3],
		Day:          headerBytes[4],
		ProductCode:  headerBytes[29],
		LicenseCode:  headerBytes[30],
		DatabaseSize: headerBytes[31],
		IPCount4:     binary.LittleEndian.Uint32(headerBytes[5:9]),
		IPBase4:      binary.LittleEndian.Uint32(headerBytes[9:13]),
		IPCount6:     binary.LittleEndian.Uint32(headerBytes[13:17]),
		IPBase6:      binary.LittleEndian.Uint32(headerBytes[17:21]),
		IndexBase4:   binary.LittleEndian.Uint32(headerBytes[21:25]),
		IndexBase6:   binary.LittleEndian.Uint32(headerBytes[25:29]),
	}

	if version.ProductCode == 0 {
		return nil, fmt.Errorf("invalid IP2Location BIN file format")
	}

	return version, nil
}
