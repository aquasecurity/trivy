package notification

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

func getMachineIdentifier() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	var macAddr string
	for _, iface := range interfaces {
		if iface.HardwareAddr.String() != "" {
			macAddr = iface.HardwareAddr.String()
			break
		}
	}
	identifier := fmt.Sprintf("%s-%s-%s", hostname, macAddr, strings.ToLower(hostname))

	return identifier, nil
}

func generateMachineHash(identifier string) string {
	hash := sha256.New()
	hash.Write([]byte(identifier))
	return hex.EncodeToString(hash.Sum(nil))
}

func uniqueIdentifier() string {
	identifier, err := getMachineIdentifier()
	if err != nil {
		return ""
	}

	return generateMachineHash(fmt.Sprintf("trivy-%s", identifier))
}
