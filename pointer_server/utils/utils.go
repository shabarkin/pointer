package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var MaliciousJARMDatabase = []string{
	"00000000000000000000000000000000000000000000000000000000000000",
	"00014d16d21d21d00042d41d00041df1e57cd0b3bf64d18696fb4fce056610",
	"00014d16d21d21d07c42d41d00041d47e4e0ae17960b2a5b4fd6107fbb0926",
	"05d02d16d04d04d05c05d02d05d04d4606ef7946105f20b303b9a05200e829",
	"05d02d20d21d20d05c05d02d05d20dd7fc4c7c6ef19b77a4ca0787979cdc13",
	"05d13d20d21d20d05c05d13d05d20dd7fc4c7c6ef19b77a4ca0787979cdc13",
	"07d00016d21d21d00042d41d00041df1e57cd0b3bf64d18696fb4fce056610",
	"07d0bd0fd06d06d07c07d0bd07d06d9b2f5869a6985368a9dec764186a9175",
	"07d0bd0fd21d21d07c07d0bd07d21d9b2f5869a6985368a9dec764186a9175",
	"07d13d15d21d21d07c07d13d07d21dd7fc4c7c6ef19b77a4ca0787979cdc13",
	"07d14d16d21d21d00007d14d07d21d3fe87b802002478c27f1c0da514dbf80",
	"07d14d16d21d21d00042d41d00041d47e4e0ae17960b2a5b4fd6107fbb0926",
	"07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2",
	"07d14d16d21d21d07c07d14d07d21d4606ef7946105f20b303b9a05200e829",
	"07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175",
	"07d14d16d21d21d07c07d14d07d21dee4eea372f163361c2623582546d06f8",
	"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",
	"07d14d16d21d21d07c42d41d00041d58c7162162b6a603d3d90a2b76865b53",
	"07d14d16d21d21d07c42d43d00041d24a458a375eef0c576d23a7bab9a9fb1",
	"07d19d1ad21d21d00007d19d07d21d25f4195751c61467fa54caf42f4e2e61",
	"15d15d15d3fd15d00042d42d00042d1279af56d3d287bbc5d38e226153ba9e",
	"15d3fd16d21d21d00042d43d000000fe02290512647416dcf0a400ccbc0b6b",
	"15d3fd16d29d29d00015d3fd15d29d1f9d8d2d24bf6c1a8572e99c89f1f5f0",
	"15d3fd16d29d29d00042d43d000000ed1cf37c9a169b41886e27ba8fad60b0",
	"15d3fd16d29d29d00042d43d000000fbc10435df141b3459e26f69e76d5947",
	"15d3fd16d29d29d00042d43d000000fe02290512647416dcf0a400ccbc0b6b",
	"16d16d16d00000022c43d43d00043d370cd49656587484eb806b90846875a0",
	"1dd28d28d00028d00042d41d00041df1e57cd0b3bf64d18696fb4fce056610",
	"1dd28d28d00028d1dc1dd28d1dd28d3fe87b802002478c27f1c0da514dbf80",
	"21b10b00021b21b21b21b10b21b21b3b0d229d76f2fd7cb8e23bb87da38a20",
	"21d10d00021d21d21c21d10d21d21d696c1bb221f80034f540b6754152d3b8",
	"21d19d00021d21d21c42d43d000000624c0617d7b1f32125cdb5240cd23ec9",
	"29d29d00029d29d00029d29d29d29de1a3c0d7ca6ad8388057924be83dfc6a",
	"29d29d00029d29d08c29d29d29d29dcd113334714fbefb4b0aba4000bcef62",
	"29d29d00029d29d21c29d29d29d29dce7a321e4956e8298ba917e9f2c22849",
	"29d29d15d29d29d21c29d29d29d29d7329fbe92d446436f2394e041278b8b2",
	"2ad00016d2ad2ad22c42d42d00042ddb04deffa1705e2edc44cae1ed24a4da",
	"2ad2ad0002ad2ad0002ad2ad2ad2ade1a3c0d7ca6ad8388057924be83dfc6a",
	"2ad2ad0002ad2ad00042d42d000000301510f56407964db9434a9bb0d4ee4a",
	"2ad2ad0002ad2ad00042d42d0000005d86ccb1a0567e012264097a0315d7a7",
	"2ad2ad0002ad2ad22c2ad2ad2ad2ad6a7bd8f51d54bfc07e1cd34e5ca50bb3",
	"2ad2ad0002ad2ad22c2ad2ad2ad2adce7a321e4956e8298ba917e9f2c22849",
	"2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da",
	"2ad2ad16d2ad2ad22c42d42d00042d58c7162162b6a603d3d90a2b76865b53",
	"2ad2ad16d2ad2ad22c42d42d00042de4f6cde49b80ad1e14c340f9e47ccd3a",
	"3fd3fd15d3fd3fd00042d42d00000061256d32ed7779c14686ad100544dc8d",
	"3fd3fd15d3fd3fd21c3fd3fd3fd3fdc110bab2c0a19e5d4e587c17ce497b15",
	"3fd3fd15d3fd3fd21c42d42d0000006f254909a73bf62f6b28507e9fb451b5",
}

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

func (this *CobaltStrikeStruct) matchJarm() bool {
	for i := 0; i < len(MaliciousJARMDatabase); i++ {
		if this.Jarm == MaliciousJARMDatabase[i] {
			return true
		}
	}
	return false
}

func (this *CobaltStrikeStruct) matchResponse() bool {
	for _, v := range this.Responses {
		if v == "404/0" {
			return true
		}
	}
	return false
}

func (this *CobaltStrikeStruct) Vote() {

	if this.Certificate == "Major Cobalt Strike" {
		this.Probability = 1.0
		return
	} else if this.Beacons != nil {
		this.Probability = 1.0
		return
	} else if this.matchJarm() && this.matchResponse() {
		this.Probability = 0.7
		return
	} else {
		this.Probability = 0.0
	}
}

var TableTargets string = "Targets"
var TableBeacons string = "Beacons"
var TableResponse string = "Responses"

type Sorter struct {
	Ports        map[string][]string
	Responses    map[string]map[string]string
	Jarms        map[string]string
	Certificates map[string]string
	Beacons      map[string][]string
}

func (this *Sorter) Init() {
	this.Ports = make(map[string][]string)
	this.Responses = make(map[string]map[string]string)
	this.Jarms = make(map[string]string)
	this.Certificates = make(map[string]string)
	this.Beacons = make(map[string][]string)
}

func (this *Sorter) Sort() (targets []CobaltStrikeStruct) {

	// all ips are initiated in responses
	for k, v := range this.Responses {
		t := &CobaltStrikeStruct{}

		t.Ip = k
		t.Responses = make(map[string]string)
		t.Responses = v

		if value, ok := this.Beacons[t.Ip]; ok {
			t.Beacons = value
		}
		if value, ok := this.Ports[t.Ip]; ok {
			t.Ports = value
		}
		if value, ok := this.Certificates[t.Ip]; ok {
			t.Certificate = value
		}
		if value, ok := this.Jarms[t.Ip]; ok {
			t.Jarm = value
		}
		targets = append(targets, *t)
	}
	return targets
}

func Voter(targets []CobaltStrikeStruct) []CobaltStrikeStruct {
	for i := 0; i < len(targets); i++ {
		targets[i].Vote()
	}
	return targets
}

var CONFIG_STRUCT = map[int]string{
	1:  "dns_ssl",
	2:  "port",
	3:  ".sleeptime",
	4:  ".http-get.server.output",
	5:  ".jitter",
	6:  ".maxdns",
	7:  "publickey",
	8:  ".http-get.uri",
	9:  ".user-agent",
	10: ".http-post.uri",
	11: ".http-get.server.output",
	12: ".http-get.client",
	13: ".http-post.client",
	14: ".spawto",
	15: ".pipename",
	16: ".killdate_year",
	17: ".killdate_month",
	18: ".killdate_day",
	19: ".dns_idle",
	20: ".dns_sleep ",
	26: ".http-get.verb",
	27: ".http-post.verb",
	28: "shouldChunkPosts",
	29: ".post-ex.spawnto_x86",
	30: ".post-ex.spawnto_x64",
	31: ".cryptoscheme",
	35: ".proxy_type",
	37: ".watermark",
	38: ".stage.cleanup",
	39: "CFGCaution",
	40: "killdate",
	41: "text_section",
	42: "obfuscate_section",
	43: "process-inject-start-rwx",
	44: "process-inject-use-rwx",
	45: "process-inject-min_alloc",
	46: "process-inject-transform-x86",
	47: "process-inject-transform-x64",
	50: "cookieBeacon",
	51: "process-inject-execute",
	52: "process-inject-allocation-method",
	53: "process-inject-stub",
	54: "host_header",
	55: "funk",
}

var Config ScanSettings = LoadAppConfig()

func LoadAppConfig() ScanSettings {
	Config := ScanSettings{}
	Config.Ports = []int{22, 80, 443, 444, 1234, 2000, 2222, 3000, 3780, 4000, 4443, 6379, 7443, 8443, 8080, 8081, 8082, 8087, 8088, 8099, 8089, 8090, 8181, 8888, 8889, 9443, 50050}
	Config.HttpBeaconDelay = 20000
	Config.HttpDelay = 8000
	Config.PortDelay = 5000
	Config.Concurrency = 120
	return Config
}

func GetConfiguredClient(http_delay int) *http.Client {

	timeout := time.Duration(http_delay * 1000000)

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	var tr = &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: re,
		Timeout:       timeout,
	}
	return client
}

func CheckKeyRawData(key string) bool {
	if key == "publickey" || key == "obfuscate_section" || key == ".spawto" || key == "process-inject-stub" || key == "process-inject-execute" {
		return true
	}
	return false
}

func ClearRawData(v []byte, all bool) []byte {
	t := bytes.ReplaceAll(v, []byte("\u0000"), []byte(""))

	if all {
		cleanBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30}
		for _, byteToClean := range cleanBytes {
			t = bytes.ReplaceAll(t, []byte{byteToClean}, []byte(" "))
		}
	}

	return t
}

func CheckDict(key int, dict map[int]string) bool {
	for k, _ := range dict {
		if k == key {
			return true
		}
	}
	return false
}

func CheckPort(host string, port_to_check int) bool {
	port := strings.Split(host, ":")[1]
	if strconv.Itoa(port_to_check) == port {
		return true
	} else {
		return false
	}
}

func ValidateOutput(output string, sort *Sorter) {
	if strings.Contains(output, "Service") {
		host := strings.Split(output, "|")[1]
		ip := strings.Split(host, ":")[0]
		port := strings.Split(host, ":")[1]
		sort.Ports[ip] = append(sort.Ports[ip], port)
	} else if strings.Contains(output, "Jarm") {
		ip := strings.Split(strings.Split(output, "|")[1], ":")[0]
		jarm := strings.Split(output, "|")[2]
		sort.Jarms[ip] = jarm
	} else if strings.Contains(output, "Certificate") {
		ip := strings.Split(strings.Split(output, "|")[1], ":")[0]
		cert := strings.Split(output, "|")[2]
		sort.Certificates[ip] = cert
	} else if strings.Contains(output, "Response") {
		uri := strings.Split(output, "|")[1]
		response := strings.Split(output, "|")[2]
		ip := strings.Split(strings.Split(uri, "://")[1], ":")[0]
		sort.Responses[ip][uri] = response
	} else if strings.Contains(output, "Beacon") {
		beaconUri := strings.Split(output, "|")[1]
		ip := strings.Split(strings.Split(beaconUri, "://")[1], ":")[0]
		sort.Beacons[ip] = append(sort.Beacons[ip], beaconUri)
	}
}

func LoadDynamoDBService() *dynamodb.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalln("Unable to load SDK config")
	}
	return dynamodb.NewFromConfig(cfg)
}

func WriteBatchTarget(svc *dynamodb.Client, targets []CobaltStrikeStruct) {

	request := make(map[string][]types.WriteRequest)

	for _, target := range targets {
		av, err := attributevalue.MarshalMap(target)
		if err != nil {
			log.Fatalf("Got error marshalling scan item: %s", err)
		}

		request[TableTargets] = append(request[TableTargets], types.WriteRequest{
			PutRequest: &types.PutRequest{
				Item: av,
			}})

	}

	input := &dynamodb.BatchWriteItemInput{
		RequestItems: request,
	}

	_, err := svc.BatchWriteItem(context.TODO(), input)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func WriteBatchBeacons(svc *dynamodb.Client, beacons []CobaltStrikeBeaconStruct) {

	request := make(map[string][]types.WriteRequest)

	for _, beacon := range beacons {
		av, err := attributevalue.MarshalMap(beacon)
		if err != nil {
			log.Fatalf("Got error marshalling scan item: %s", err)
		}

		request[TableBeacons] = append(request[TableBeacons], types.WriteRequest{
			PutRequest: &types.PutRequest{
				Item: av,
			}})

	}

	input := &dynamodb.BatchWriteItemInput{
		RequestItems: request,
	}

	_, err := svc.BatchWriteItem(context.TODO(), input)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func WriteResponse(svc *dynamodb.Client, response ScanResponse) {
	av, err := attributevalue.MarshalMap(response)
	if err != nil {
		log.Fatalf("Got error marshalling scan item: %s", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(TableResponse),
		Item:      av,
	}
	_, err = svc.PutItem(context.TODO(), input)
	if err != nil {
		log.Fatalf("Got error calling PutItem: %s", err)
	}
}

func WriteTarget(svc *dynamodb.Client, target CobaltStrikeStruct) {
	av, err := attributevalue.MarshalMap(target)
	if err != nil {
		log.Fatalf("Got error marshalling scan item: %s", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(TableTargets),
		Item:      av,
	}
	_, err = svc.PutItem(context.TODO(), input)
	if err != nil {
		log.Fatalf("Got error calling PutItem: %s", err)
	}
}

func WriteBeacon(svc *dynamodb.Client, beacon CobaltStrikeBeaconStruct) {
	av, err := attributevalue.MarshalMap(beacon)

	if err != nil {
		log.Fatalf("Got error marshalling scan item: %s", err)
	}

	input := &dynamodb.PutItemInput{
		TableName: aws.String(TableBeacons),
		Item:      av,
	}
	_, err = svc.PutItem(context.TODO(), input)
	if err != nil {
		log.Fatalf("Got error calling PutItem: %s", err)
	}
}

func Min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
