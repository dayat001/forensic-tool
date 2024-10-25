package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// ForensicData struktur utama untuk menyimpan semua informasi
type ProcessInfo struct {
	PID           int32    `json:"pid"`
	Name          string   `json:"name"`
	Username      string   `json:"username"`
	Status        []string `json:"status"` // Diubah dari string menjadi []string
	CreationTime  string   `json:"creation_time"`
	MemoryUsage   uint64   `json:"memory_usage"`
	CPUUsage      float64  `json:"cpu_usage"`
	OpenFiles     []string `json:"open_files"`
}

// VolatileInfo menyimpan informasi yang bersifat volatile
type VolatileInfo struct {
	ProcessInfo    []ProcessInfo    `json:"process_info"`
	NetworkInfo    []NetworkInfo    `json:"network_info"`
	SystemState    SystemState      `json:"system_state"`
	MemoryInfo     MemoryInfo       `json:"memory_info"`
	SwapInfo       SwapInfo         `json:"swap_info"`
}

// NonVolatileInfo menyimpan informasi yang bersifat non-volatile
type NonVolatileInfo struct {
	SystemInfo     SystemInfo       `json:"system_info"`
	FileSystemInfo []FileSystemInfo `json:"filesystem_info"`
	InstalledApps  []string        `json:"installed_applications"`
	UserActivity   UserActivity     `json:"user_activity"`
}

type NetworkInfo struct {
	Interface   string   `json:"interface"`
	LocalAddr   string   `json:"local_addr"`
	RemoteAddr  string   `json:"remote_addr"`
	Status      string   `json:"status"`
	Connections []string `json:"connections"`
}

type SystemState struct {
	Uptime       float64  `json:"uptime"`
	LoadAverage  []float64`json:"load_average"`
	CurrentUsers []string `json:"current_users"`
}

type MemoryInfo struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

type SwapInfo struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

type SystemInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Platform     string `json:"platform"`
	KernelVersion string `json:"kernel_version"`
	CPUInfo      []cpu.InfoStat `json:"cpu_info"`
}

type FileSystemInfo struct {
	Device      string  `json:"device"`
	MountPoint  string  `json:"mountpoint"`
	FSType      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

type UserActivity struct {
	RecentFiles    []string `json:"recent_files"`
	BrowserHistory []string `json:"browser_history"`
	SystemLogs     []string `json:"system_logs"`
}

// ForensicCollector struktur untuk mengumpulkan data
type ForensicData struct {
    Volatile       VolatileInfo     `json:"volatile_info"`
    NonVolatile    NonVolatileInfo  `json:"non_volatile_info"`
    SystemSummary  string           `json:"system_summary"`
    CollectionTime string           `json:"collection_time"`
}

// NewForensicCollector membuat instance baru
type ForensicCollector struct {
    Data ForensicData
}

// NewForensicCollector membuat instance baru dari ForensicCollector
func NewForensicCollector() *ForensicCollector {
    return &ForensicCollector{
        Data: ForensicData{
            CollectionTime: time.Now().Format(time.RFC3339),
        },
    }
}

// Di bagian CollectVolatileInfo, ubah bagian proses collection:
func (fc *ForensicCollector) CollectVolatileInfo() error {
	// Collect Process Information
	processes, err := process.Processes()
	if err != nil {
		return fmt.Errorf("error collecting processes: %v", err)
	}

	for _, p := range processes {
		name, _ := p.Name()
		username, _ := p.Username()
		status, _ := p.Status()  // status sudah berupa []string
		createTime, _ := p.CreateTime()
		memInfo, _ := p.MemoryInfo()
		cpuPercent, _ := p.CPUPercent()
		
		var memoryUsage uint64
		if memInfo != nil {
			memoryUsage = memInfo.RSS
		}

		openFiles := []string{}
		if files, err := p.OpenFiles(); err == nil {
			for _, f := range files {
				openFiles = append(openFiles, f.Path)
			}
		}

		fc.Data.Volatile.ProcessInfo = append(fc.Data.Volatile.ProcessInfo, ProcessInfo{
			PID:          p.Pid,
			Name:         name,
			Username:     username,
			Status:       status,  // Sekarang status adalah []string
			CreationTime: time.Unix(createTime/1000, 0).Format(time.RFC3339),
			MemoryUsage:  memoryUsage,
			CPUUsage:     cpuPercent,
			OpenFiles:    openFiles,
		})
	}

	// Collect Memory Information
	virtualMem, err := mem.VirtualMemory()
	if err == nil {
		fc.Data.Volatile.MemoryInfo = MemoryInfo{
			Total:       virtualMem.Total,
			Used:        virtualMem.Used,
			Free:        virtualMem.Free,
			UsedPercent: virtualMem.UsedPercent,
		}
	}

	// Collect Swap Information
	swapMem, err := mem.SwapMemory()
	if err == nil {
		fc.Data.Volatile.SwapInfo = SwapInfo{
			Total:       swapMem.Total,
			Used:        swapMem.Used,
			Free:        swapMem.Free,
			UsedPercent: swapMem.UsedPercent,
		}
	}

	// Collect Network Information
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			netInfo := NetworkInfo{
				Interface: iface.Name,
				Connections: []string{},
			}
			
			conns, err := net.Connections("all")
			if err == nil {
				for _, conn := range conns {
					netInfo.Connections = append(netInfo.Connections,
						fmt.Sprintf("%v:%v -> %v:%v (%s)",
							conn.Laddr.IP, conn.Laddr.Port,
							conn.Raddr.IP, conn.Raddr.Port,
							conn.Status))
				}
			}
			
			fc.Data.Volatile.NetworkInfo = append(fc.Data.Volatile.NetworkInfo, netInfo)
		}
	}

	// Collect System State
	hostInfo, _ := host.Info()
	loadInfo, _ := load.Avg()
	
	fc.Data.Volatile.SystemState = SystemState{
		Uptime:      float64(hostInfo.Uptime),
		LoadAverage: []float64{loadInfo.Load1, loadInfo.Load5, loadInfo.Load15},
	}

	return nil
}

// CollectNonVolatileInfo mengumpulkan informasi non-volatile
func (fc *ForensicCollector) CollectNonVolatileInfo() error {
	// Collect System Information
	hostInfo, err := host.Info()
	if err == nil {
		cpuInfo, _ := cpu.Info()
		
		fc.Data.NonVolatile.SystemInfo = SystemInfo{
			Hostname:      hostInfo.Hostname,
			OS:           hostInfo.OS,
			Platform:     hostInfo.Platform,
			KernelVersion: hostInfo.KernelVersion,
			CPUInfo:      cpuInfo,
		}
	}

	// Collect Filesystem Information
	partitions, err := disk.Partitions(true)
	if err == nil {
		for _, partition := range partitions {
			usage, err := disk.Usage(partition.Mountpoint)
			if err == nil {
				fc.Data.NonVolatile.FileSystemInfo = append(fc.Data.NonVolatile.FileSystemInfo, FileSystemInfo{
					Device:      partition.Device,
					MountPoint:  partition.Mountpoint,
					FSType:      partition.Fstype,
					Total:       usage.Total,
					Used:        usage.Used,
					Free:        usage.Free,
					UsedPercent: usage.UsedPercent,
				})
			}
		}
	}

	// Collect Installed Applications
	cmd := exec.Command("dpkg", "--get-selections")
	output, err := cmd.Output()
	if err == nil {
		apps := strings.Split(string(output), "\n")
		fc.Data.NonVolatile.InstalledApps = apps
	}

	// Collect User Activity
	homeDir, err := os.UserHomeDir()
	if err == nil {
		// Recent Files
		recentFiles := []string{}
		err := filepath.Walk(homeDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && time.Since(info.ModTime()) < 24*time.Hour {
				recentFiles = append(recentFiles, path)
			}
			return nil
		})
		if err == nil {
			fc.Data.NonVolatile.UserActivity.RecentFiles = recentFiles
		}

		// Browser History (Firefox sebagai contoh)
		firefoxPath := filepath.Join(homeDir, ".mozilla/firefox")
		if _, err := os.Stat(firefoxPath); err == nil {
			fc.Data.NonVolatile.UserActivity.BrowserHistory = append(
				fc.Data.NonVolatile.UserActivity.BrowserHistory,
				"Firefox history tersedia di: "+firefoxPath)
		}
	}

	// System Logs
	logFiles, err := ioutil.ReadDir("/var/log")
	if err == nil {
		for _, f := range logFiles {
			fc.Data.NonVolatile.UserActivity.SystemLogs = append(
				fc.Data.NonVolatile.UserActivity.SystemLogs,
				filepath.Join("/var/log", f.Name()))
		}
	}

	return nil
}

// GenerateSystemSummary membuat ringkasan sistem
func (fc *ForensicCollector) GenerateSystemSummary() {
	summary := strings.Builder{}
	summary.WriteString("EXECUTIVE SUMMARY\n")
	summary.WriteString("================\n\n")
	
	// System Information
	summary.WriteString(fmt.Sprintf("System: %s %s\n", 
		fc.Data.NonVolatile.SystemInfo.Platform,
		fc.Data.NonVolatile.SystemInfo.KernelVersion))
	summary.WriteString(fmt.Sprintf("Hostname: %s\n", 
		fc.Data.NonVolatile.SystemInfo.Hostname))
	
	// Memory Usage
	summary.WriteString(fmt.Sprintf("\nMemory Usage: %.2f%%\n", 
		fc.Data.Volatile.MemoryInfo.UsedPercent))
	summary.WriteString(fmt.Sprintf("Swap Usage: %.2f%%\n", 
		fc.Data.Volatile.SwapInfo.UsedPercent))
	
	// Process Statistics
	summary.WriteString(fmt.Sprintf("\nTotal Processes: %d\n", 
		len(fc.Data.Volatile.ProcessInfo)))
	
	// Network Connections
	totalConnections := 0
	for _, net := range fc.Data.Volatile.NetworkInfo {
		totalConnections += len(net.Connections)
	}
	summary.WriteString(fmt.Sprintf("Network Connections: %d\n", totalConnections))
	
	// File Systems
	summary.WriteString("\nFile System Usage:\n")
	for _, fs := range fc.Data.NonVolatile.FileSystemInfo {
		summary.WriteString(fmt.Sprintf("- %s: %.2f%% used\n", 
			fs.MountPoint, fs.UsedPercent))
	}
	
	// User Activity
	summary.WriteString(fmt.Sprintf("\nRecent Files (24h): %d\n", 
		len(fc.Data.NonVolatile.UserActivity.RecentFiles)))
	
	// Installed Applications
	summary.WriteString(fmt.Sprintf("Installed Applications: %d\n", 
		len(fc.Data.NonVolatile.InstalledApps)))

	fc.Data.SystemSummary = summary.String()
}

// SaveReport menyimpan hasil ke file JSON
func (fc *ForensicCollector) SaveReport(filename string) error {
	data, err := json.MarshalIndent(fc.Data, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshaling data: %v", err)
	}

	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}

	// Save executive summary to separate file
	summaryFilename := strings.TrimSuffix(filename, ".json") + "_summary.txt"
	err = ioutil.WriteFile(summaryFilename, []byte(fc.Data.SystemSummary), 0644)
	if err != nil {
		return fmt.Errorf("error writing summary file: %v", err)
	}

	return nil
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("This program requires root privileges. Please run with sudo.")
	}

	collector := NewForensicCollector()

	fmt.Println("Collecting volatile information...")
	if err := collector.CollectVolatileInfo(); err != nil {
		log.Printf("Error collecting volatile info: %v", err)
	}

	fmt.Println("Collecting non-volatile information...")
	if err := collector.CollectNonVolatileInfo(); err != nil {
		log.Printf("Error collecting non-volatile info: %v", err)
	}

	fmt.Println("Generating system summary...")
	collector.GenerateSystemSummary()

	fmt.Println("Saving reports...")
	if err := collector.SaveReport("forensic_report.json"); err != nil {
		log.Fatalf("Error saving report: %v", err)
	}

	fmt.Println("Forensic analysis complete. Results saved to forensic_report.json")
}