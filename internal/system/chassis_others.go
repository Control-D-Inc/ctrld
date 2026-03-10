//go:build !darwin

package system

import "github.com/jaypipes/ghw"

// GetChassisInfo retrieves hardware information including machine model type and vendor from the system profiler.
func GetChassisInfo() (*ChassisInfo, error) {
	// Disable warnings from ghw, since these are undesirable but recoverable errors.
	// With warnings enabled, ghw will emit unnecessary log messages.
	chassis, err := ghw.Chassis(ghw.WithDisableWarnings())
	if err != nil {
		return nil, err
	}
	info := &ChassisInfo{
		Type:   chassis.TypeDescription,
		Vendor: chassis.Vendor,
	}
	return info, nil
}
