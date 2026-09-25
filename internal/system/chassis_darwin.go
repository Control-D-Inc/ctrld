package system

import (
	"errors"
	"fmt"

	"github.com/brunogui0812/sysprofiler"
)

// GetChassisInfo retrieves hardware information including machine model type and vendor from the system profiler.
func GetChassisInfo() (*ChassisInfo, error) {
	hardwares, err := sysprofiler.Hardware()
	if err != nil {
		return nil, fmt.Errorf("failed to get hardware info: %w", err)
	}
	if len(hardwares) == 0 {
		return nil, errors.New("no hardware info found")
	}
	hardware := hardwares[0]
	info := &ChassisInfo{
		Type:   hardware.MachineModel,
		Vendor: "Apple Inc.",
	}
	return info, nil
}
