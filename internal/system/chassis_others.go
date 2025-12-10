//go:build !darwin

package system

import "github.com/jaypipes/ghw"

// GetChassisInfo retrieves hardware information including machine model type and vendor from the system profiler.
func GetChassisInfo() (*ChassisInfo, error) {
	chassis, err := ghw.Chassis()
	if err != nil {
		return nil, err
	}
	info := &ChassisInfo{
		Type:   chassis.TypeDescription,
		Vendor: chassis.Vendor,
	}
	return info, nil
}
