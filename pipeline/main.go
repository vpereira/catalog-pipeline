package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
)

// Constants
const (
	Image          = "registry.suse.com/bci/bci-busybox:latest"
	BaseDir        = "/tmp"
	ReportSizeURL  = "http://localhost:8080/foo/bar"
	ReportTrivyURL = "http://localhost:8080/bar/foo"
)

// ImageDetails contains the architecture and the path to the downloaded image.
type ImageDetails struct {
	Architecture string
	FilePath     string
}

// ImageSize contains the architecture and the size of the image.
type ImageSize struct {
	Architecture string `json:"architecture"`
	Size         int64  `json:"size"`
}

// TrivyReport contains the architecture and the Trivy report for the image.
type TrivyReport struct {
	Architecture string `json:"architecture"`
	Report       string `json:"report"`
}

func main() {
	ctx := context.Background()
	architectures, err := getSupportedArchitectures(Image)
	if err != nil {
		log.Fatalf("Error getting architectures: %v", err)
	}

	downloadDir, err := os.MkdirTemp(BaseDir, "skopeo_downloads-*")
	if err != nil {
		log.Fatalf("Error creating temp directory: %v", err)
	}
	defer os.RemoveAll(downloadDir)

	imageChan := make(chan ImageDetails)
	sizeChan := make(chan ImageSize)
	reportChan := make(chan TrivyReport)

	var wg sync.WaitGroup
	var wg2 sync.WaitGroup

	// Fan out the download tasks
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		for _, arch := range architectures {
			wg.Add(1)
			go func(arch string) {
				defer wg.Done()
				filePath := filepath.Join(downloadDir, sanitizeImageName(fmt.Sprintf("%s_%s.tar", Image, arch)))
				fmt.Printf("Downloading image for architecture %s to %s\n", arch, filePath)
				if err := downloadImage(ctx, Image, arch, filePath); err != nil {
					log.Printf("Error downloading image for architecture %s: %v", arch, err)
					return
				}
				imageChan <- ImageDetails{Architecture: arch, FilePath: filePath}
			}(arch)
		}
		wg.Wait()
		close(imageChan)
	}()

	// Size emission job
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		for img := range imageChan {
			size, err := getFileSize(img.FilePath)
			if err != nil {
				log.Printf("Error getting file size for %s: %v", img.Architecture, err)
				continue
			}
			sizeChan <- ImageSize{Architecture: img.Architecture, Size: size}
		}
		close(sizeChan)
	}()

	// Trivy report generation job
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		for img := range imageChan {
			report, err := generateTrivyReport(ctx, img.FilePath)
			if err != nil {
				log.Printf("Error generating Trivy report for %s: %v", img.Architecture, err)
				continue
			}
			reportChan <- TrivyReport{Architecture: img.Architecture, Report: report}
		}
		close(reportChan)
	}()

	// Collect and post size results
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		sizes := make(map[string]int64)
		for size := range sizeChan {
			sizes[size.Architecture] = size.Size
		}
		if err := postJSON(ReportSizeURL, sizes); err != nil {
			log.Printf("Error posting sizes: %v", err)
		}
	}()

	// Collect and post Trivy reports
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		reports := make(map[string]string)
		for report := range reportChan {
			reports[report.Architecture] = report.Report
		}
		if err := postJSON(ReportTrivyURL, reports); err != nil {
			log.Printf("Error posting Trivy reports: %v", err)
		}
	}()

	wg2.Wait()
}

// sanitizeImageName replaces slashes and colons in the image name with underscores.
func sanitizeImageName(image string) string {
	return strings.NewReplacer("/", "_", ":", "_").Replace(image)
}

// getSupportedArchitectures gets the list of supported architectures for a Docker image.
func getSupportedArchitectures(image string) ([]string, error) {
	cmdArgs := []string{"inspect", "--raw", fmt.Sprintf("docker://%s", image)}
	fmt.Printf("cmdArgs: %v\n", cmdArgs)
	cmd := exec.Command("skopeo", cmdArgs...)
	output, err := cmd.Output()

	if err != nil {
		return nil, err
	}

	var manifest struct {
		Manifests []struct {
			Platform struct {
				Architecture string `json:"architecture"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(output, &manifest); err != nil {
		return nil, err
	}

	var architectures []string
	for _, m := range manifest.Manifests {
		architectures = append(architectures, m.Platform.Architecture)
	}

	// Ensure at least "amd64" is included if no architectures were found
	if len(architectures) == 0 {
		architectures = []string{"amd64"}
	}

	return architectures, nil
}

// downloadImage downloads the Docker image for a specific architecture.
func downloadImage(ctx context.Context, image, architecture, filePath string) error {
	cmdArgs := []string{"copy", "--remove-signatures", "--override-arch", architecture, fmt.Sprintf("docker://%s", image), fmt.Sprintf("docker-archive://%s", filePath)}

	// Check and add registry credentials if they are set
	registryUsername, usernameSet := os.LookupEnv("REGISTRY_USERNAME")
	registryPassword, passwordSet := os.LookupEnv("REGISTRY_PASSWORD")
	if usernameSet && passwordSet {
		cmdArgs = append(cmdArgs, "--src-username", registryUsername, "--src-password", registryPassword)
	}

	cmd := exec.CommandContext(ctx, "skopeo", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// getFileSize returns the size of the file at the given path in bytes.
func getFileSize(filePath string) (int64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return fileInfo.Size(), nil
}

// generateTrivyReport generates a Trivy report for the specified image file.
func generateTrivyReport(ctx context.Context, filePath string) (string, error) {
	resultFileName := filepath.Join(BaseDir, "trivy_report.json")
	cmdArgs := generateTrivyCmdArgs(resultFileName, filePath)
	cmd := exec.CommandContext(ctx, "trivy", cmdArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("trivy output: %s, error: %s", string(output), err.Error())
	}
	if _, err = os.Stat(resultFileName); err != nil {
		return "", fmt.Errorf("trivy report file not found")
	}
	output, _ = os.ReadFile(resultFileName)
	return string(output), nil
}

// GenerateTrivyCmdArgs generates the command line arguments for the trivy command based on environment variables and input parameters.
func generateTrivyCmdArgs(resultFileName, target string) []string {
	cmdArgs := []string{"image"}

	// Check if SLOW_RUN environment variable is set to "1" and add "--slow" parameter
	slowRun := os.Getenv("SLOW_RUN")
	if slowRun == "1" {
		cmdArgs = append(cmdArgs, "--slow")
	}

	cmdArgs = append(cmdArgs, "--format", "json", "--output", resultFileName, "--input", target)

	return cmdArgs
}

// postJSON posts the given data as JSON to the specified URL.
func postJSON(url string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := http.Post(url, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-200 response code: %d", resp.StatusCode)
	}
	return nil
}
