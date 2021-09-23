package utils

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/joho/godotenv"
)

var Yellow = color.New(color.FgYellow).SprintFunc()
var Red = color.New(color.FgRed).SprintFunc()
var White = color.New(color.FgWhite).SprintFunc()
var Cyan = color.New(color.FgCyan).SprintFunc()
var Green = color.New(color.FgGreen).SprintFunc()
var Magenta = color.New(color.FgMagenta).SprintFunc()

type ScanTargets struct {
	Ips []string `json:"ips"`
}

type ScanSettings struct {
	Ports           []int `json:"ports"`
	HttpBeaconDelay int   `json:"http_beacon_delay"`
	HttpDelay       int   `json:"http_delay"`
	PortDelay       int   `json:"port_delay"`
	Concurrency     int   `json:"concurrency"`
}

type ScanRequest struct {
	PacketId int          `json:"packet_id"`
	Setting  ScanSettings `json:"scan_settings"`
	Targets  ScanTargets  `json:"scan_targets"`
}

type ScanResponse struct {
	PacketId int    `json:"packet_id"`
	Time     string `json:"time"`
	Ports    int    `json:"ports"`
	Services int    `json:"services"`
	Beacons  int    `json:"beacons"`
}

type CobaltStrikeBeaconStruct struct {
	Uri          string
	BeaconConfig map[string]string
}

type CobaltStrikeStruct struct {
	Ip          string
	Ports       []string
	Responses   map[string]string
	Jarm        string
	Certificate string
	Beacons     []string
	Probability float32
}

// DynamoDB Outout directory
var DirName = "results/"

// DynamoDB table names
var TableTargets string = "Targets"
var TableBeacons string = "Beacons"
var TableResponses string = "Responses"

// Lambda configurations
var BatchSize int = 10
var LambdaMemory int32 = 3009
var LambdaTimeout int32 = 60
var Concurrency = 120

// Autodeploy configurations
var LambdaFunction string = "pointer"
var IAMRoleName string = "pointer"
var SQSQueue string = "pointer"

var ReadCapacityUnits int64 = 40
var WriteCapacityUnits int64 = 40

func LoadTargets(filename string) (targets ScanTargets) {
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		file, _ := ioutil.ReadFile(filename)

		err = json.Unmarshal(file, &targets)
		if err != nil {
			return ScanTargets{}
		}
	}
	return targets
}

func BatchTargets(filename string) (requests []ScanRequest) {
	Targets := LoadTargets(filename)

	r := ScanRequest{
		Setting: ScanSettings{
			Ports:           []int{22, 80, 443, 444, 1234, 2000, 2222, 3000, 3780, 4000, 4443, 6379, 7443, 8443, 8080, 8081, 8082, 8087, 8088, 8099, 8089, 8090, 8181, 8888, 8889, 9443, 50050},
			HttpBeaconDelay: 20000,
			HttpDelay:       8000,
			PortDelay:       5000,
			Concurrency:     Concurrency,
		},
	}
	packet_id := 1

	for i := 0; i < len(Targets.Ips); i += BatchSize {

		r.PacketId = packet_id
		r.Targets = ScanTargets{Ips: Targets.Ips[i:Min(i+BatchSize, len(Targets.Ips))]}

		packet_id += 1
		requests = append(requests, r)
	}

	return requests
}

func Min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

func CreateDirectory(dirName string) {
	if _, err := os.Stat(dirName); os.IsNotExist(err) {
		os.Mkdir(dirName, 0755)
	}
}

func WriteResponses(fileName string, responses []ScanResponse) {
	CreateDirectory(DirName)

	filename := DirName + fileName
	var jsonfile *os.File
	defer jsonfile.Close()

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		jsonfile, err = os.Create(filename)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed creating file: %s", err)
		}

	} else {
		jsonfile, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed appending to a file: %s", err)
		}
	}

	json, err := json.Marshal(responses)
	if err != nil {
		log.Fatal("Failed to generate json", err)
	}
	jsonfile.Write(json)
}

var BeaconHeadliner = []string{
	"uri",
	".http-get.uri",
	".http-post.uri",
	".http-get.client",
	".http-post.client",
	".user-agent",
	".watermark",
	".sleeptime",
	".jitter",
	".http-get.verb",
	".http-post.verb",
	".http-get.server.output",
	".post-ex.spawnto_x86",
	".post-ex.spawnto_x64",
	".maxdns",
	"dns_ssl",
	".dns_idle",
	".dns_sleep ",
	".pipename",
	".killdate_year",
	".killdate_month",
	".killdate_day",
	"shouldChunkPosts",
	".cryptoscheme",
	".proxy_type",
	".stage.cleanup",
	"CFGCaution",
	"killdate",
	"text_section",
	"cookieBeacon",
	"publickey",
	".spawto",
	"obfuscate_section",
	"process-inject-start-rwx",
	"process-inject-use-rwx",
	"process-inject-min_alloc",
	"process-inject-transform-x86",
	"process-inject-transform-x64",
	"process-inject-execute",
	"process-inject-allocation-method",
	"process-inject-stub",
	"host_header",
	"funk",
}

var TargetHeadliner = []string{
	"ip",
	"probability",
	"jarm",
	"certificate",
	"ports",
	"responses",
	"beacons",
}

func WriteCobaltStrikeBeacons(fileName string, beacons []CobaltStrikeBeaconStruct) {
	CreateDirectory(DirName)

	filename := DirName + fileName
	var jsonfile *os.File
	defer jsonfile.Close()

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		jsonfile, err = os.Create(filename)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed creating file: %s", err)
		}

	} else {
		jsonfile, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed appending to a file: %s", err)
		}
	}

	json, err := json.Marshal(beacons)
	if err != nil {
		log.Fatal("Failed to generate json", err)
	}
	jsonfile.Write(json)
}

func WriteCobaltStrikeBeaconsCSV(fileName string, beacons []CobaltStrikeBeaconStruct) {
	CreateDirectory(DirName)

	filename := DirName + fileName
	var csvwriter *csv.Writer
	var csvfile *os.File

	defer csvfile.Close()

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		csvfile, err = os.Create(filename)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed creating file: %s", err)
		}
		csvwriter = csv.NewWriter(csvfile)
		csvwriter.Write(BeaconHeadliner)

	} else {
		csvfile, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed appending to a file: %s", err)
		}
		csvwriter = csv.NewWriter(csvfile)
	}

	// write to csv
	for i := 0; i < len(beacons); i++ {
		row := []string{}
		row = append(row, beacons[i].Uri)
		for k := 1; k < len(BeaconHeadliner); k++ {
			if val, ok := beacons[i].BeaconConfig[BeaconHeadliner[k]]; ok {
				row = append(row, val)
			} else {
				row = append(row, "")
			}
		}
		_ = csvwriter.Write(row)
	}

	// closing the writer descriptor and csv file
	csvwriter.Flush()
	csvfile.Close()
}

func WriteCobaltStrikeTargets(fileName string, targets []CobaltStrikeStruct) {
	CreateDirectory(DirName)

	filename := DirName + fileName
	var jsonfile *os.File
	defer jsonfile.Close()

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		jsonfile, err = os.Create(filename)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed creating file: %s", err)
		}

	} else {
		jsonfile, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed appending to a file: %s", err)
		}
	}

	json, err := json.Marshal(targets)
	if err != nil {
		log.Fatal(Yellow("[Err]: ")+"Failed to generate json", err)
	}
	jsonfile.Write(json)
}

func WriteCobaltStrikeTargetsCSV(fileName string, targets []CobaltStrikeStruct) {
	CreateDirectory(DirName)

	filename := DirName + fileName
	var csvwriter *csv.Writer
	var csvfile *os.File

	defer csvfile.Close()

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		csvfile, err = os.Create(filename)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed creating file: %s", err)
		}
		csvwriter = csv.NewWriter(csvfile)
		csvwriter.Write(TargetHeadliner)

	} else {
		csvfile, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Failed appending to a file: %s", err)
		}
		csvwriter = csv.NewWriter(csvfile)
	}

	// write to csv
	for i := 0; i < len(targets); i++ {
		row := []string{}
		row = append(row, targets[i].Ip)
		row = append(row, fmt.Sprintf("%f", targets[i].Probability))
		row = append(row, targets[i].Jarm)
		row = append(row, targets[i].Certificate)

		// ports
		if targets[i].Ports != nil {
			row = append(row, strings.Join(targets[i].Ports, ";"))
		} else {
			row = append(row, "")
		}

		// responses
		obj, err := json.Marshal(targets[i].Responses)
		if err != nil {
		}

		if obj != nil {
			row = append(row, strings.ReplaceAll(string(obj[1:len(obj)-1]), ",", ";"))
		} else {
			row = append(row, "")
		}

		// beacons
		if targets[i].Beacons != nil {
			row = append(row, strings.Join(targets[i].Beacons, ";"))
		} else {
			row = append(row, "")
		}

		_ = csvwriter.Write(row)
	}

	// closing the writer descriptor and csv file
	csvwriter.Flush()
	csvfile.Close()
}

func LoadEnv() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println(Yellow("[Err]:"), "Loading `.env` file")
		os.Exit(1)
	}
}

func CreateAWScredentialsFile(aws_access_key_id, aws_secret_access_key *string) {

	awsCredentials := "AWS_REGION=us-east-2" + "\n"
	awsCredentials += "AWS_ACCESS_KEY_ID=" + *aws_access_key_id + "\n"
	awsCredentials += "AWS_SECRET_ACCESS_KEY=" + *aws_secret_access_key + "\n"
	awsCredentials += "AWS_SESSION_TOKEN=" + "\n"

	ioutil.WriteFile(".env", []byte(awsCredentials), 0644)
}
