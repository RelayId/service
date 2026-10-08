package main

import (
	"os"

	"github.com/shirou/gopsutil/v4/process"
)

type systemStatus struct {
	CPUPercent      float64 `json:"cpu_percent"`
	MemoryUsedBytes uint64  `json:"memory_used_bytes"`
}

func readSystemStatus() *systemStatus {
	value, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		return nil
	}

	cpuPercent, err := value.CPUPercent()
	if err != nil {
		return nil
	}

	memory, err := value.MemoryInfo()
	if err != nil || memory == nil {
		return nil
	}

	return &systemStatus{
		CPUPercent:      cpuPercent,
		MemoryUsedBytes: memory.RSS,
	}
}
