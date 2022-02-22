package beacon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shabarkin/pointer_server/utils"
)

func xor(a []byte, b []byte) []byte {
	return []byte{a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]}
}

func decryptBeacon(data []byte) []byte {
	ba := 0
	if bytes.HasPrefix(data, []byte{0xfc, 0xe8}) {
		if !bytes.Contains(data, []byte{0xe8, 0xd4, 0xff, 0xff, 0xff}) {
			if !bytes.Contains(data, []byte{0xe8, 0xd0, 0xff, 0xff, 0xff}) {
				return []byte{}
			} else {
				ba = bytes.Index(data, []byte{0xe8, 0xd0, 0xff, 0xff, 0xff})
			}
		} else {
			ba = bytes.Index(data, []byte{0xe8, 0xd4, 0xff, 0xff, 0xff})
		}

		ba += 5

	} else if bytes.HasPrefix(data, []byte{0xfc, 0x48}) {
		if !bytes.Contains(data, []byte{0xe8, 0xc8, 0xff, 0xff, 0xff}) {
			return []byte{}
		} else {
			ba = bytes.Index(data, []byte{0xe8, 0xc8, 0xff, 0xff, 0xff})
		}
		ba += 5
	}

	key := data[ba : ba+4]

	var res []byte
	d := []byte{}

	for i := ba + 8; i < (len(data) - ba - 8); i += 4 {
		d = data[i : i+4]
		res = []byte(string(res) + string(xor(d, key)))
		key = d
	}
	return res
}

func searchConfig(data []byte) (int, byte) {
	re, _ := regexp.Compile("ihihik.{2}ikihik")
	r := re.FindIndex(data)

	if len(r) != 0 {
		return r[0], byte(0x69)

	} else {
		re, _ := regexp.Compile("\\.\\/\\.\\/\\.\\,.{2}\\.\\,\\.\\/\\.\\,")
		r := re.FindIndex(data)

		if len(r) != 0 {
			return r[0], byte(0x2e)

		} else {
			re, _ := regexp.Compile("\x00\x01\x00\x01\x00\x02.{2}\x00\x02\x00\x01\x00\x02")
			r := re.FindIndex(data)

			if len(r) != 0 {
				return r[0], byte(0x00)
			}
		}
	}
	return 0, byte(0x00)
}

func decodeConfig(data []byte) map[string]string {

	start_idx, key := searchConfig(data)

	if start_idx == 0 && key == 0x00 {
		//fmt.Println("Start position of the config struct not found")
		return nil
	}

	var conf []byte
	var MAX_SIZE int = 3000
	for i := start_idx; i < start_idx+MAX_SIZE; i++ {
		conf = append(conf, data[i]^key)
	}

	data = conf

	// Before this all is good
	config := make(map[string]string)

	for i := 0; i < len(data)-8; {
		if data[i] == 0 && data[i+1] == 0 {
			break
		}

		var dec = []int{} // Python equivalent: struct.unpack(">HHH", data[i:i+6])
		for local_i := i; local_i <= i+4; local_i += 2 {
			dec = append(dec, int(binary.BigEndian.Uint16(data[local_i:local_i+2])))
		}

		if len(dec) != 3 {
			return nil
		}

		if dec[0] == 1 {
			// Python equivalent: struct.unpack(">H", data[i+6:i+8])[0]
			v := int(binary.BigEndian.Uint16(data[i+6 : i+8]))

			config["dns"] = fmt.Sprintf("%t", ((v & 1) == 1))
			config["ssl"] = fmt.Sprintf("%t", ((v & 8) == 8))

		} else {
			var key_small string

			if utils.CheckDict(dec[0], utils.CONFIG_STRUCT) {
				key_small = utils.CONFIG_STRUCT[dec[0]]
			}

			if key_small != "" {
				if dec[1] == 1 && dec[2] == 2 {
					config[key_small] = fmt.Sprintf("%d", binary.BigEndian.Uint16(data[i+6:i+8])) //struct.unpack(">H", data[i+6:i+8])[0]

				} else if dec[1] == 2 && dec[2] == 4 {
					config[key_small] = fmt.Sprintf("%d", binary.BigEndian.Uint32(data[i+6:i+10])) //struct.unpack(">I", data[i+6:i+10])[0]

				} else if dec[1] == 3 {
					if len(data[i+6:]) > dec[2] {
						v := data[i+6 : i+6+dec[2]]
						if utils.CheckKeyRawData(key_small) {
							config[key_small] = fmt.Sprintf("%x", bytes.ReplaceAll(v, []byte("\u0000"), []byte("")))
						} else {
							config[key_small] = fmt.Sprintf("%s", utils.ClearRawData(v, false))

						}
					}
				}
			}

		}
		i += int(dec[2]) + 6
	}
	return config
}

func parseBeacon(body []byte) map[string]string {

	if bytes.HasPrefix(body, []byte{0xfc, 0xe8}) {
		beacon := decryptBeacon(body)
		if len(beacon) != 0 {
			return decodeConfig(beacon)
		}

	} else if bytes.HasPrefix(body, []byte("MZ")) {
		return decodeConfig(body)
	}

	return nil
}

func getBeacon(client *http.Client, url string) (bool, []byte) {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, []byte("")
	}

	req.Header.Add("Connection", "close")
	req.Close = true
	resp, err := client.Do(req)

	if err != nil {
		return false, []byte("")
	}

	// check whether status code is correct
	if resp.StatusCode != 200 {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
		return false, []byte("")
	}

	// Read beacon
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
	}
	resp.Body.Close()

	return true, body
}

func GetBeaconConfig(timeout int, url string) (map[string]string, string) {

	client := utils.GetConfiguredClient(timeout)

	ok, body := getBeacon(client, url+"/aaa9")
	if ok {
		return parseBeacon(body), url + "/aaa9"
	}

	ok, body = getBeacon(client, url+"/aab9")
	if ok {
		return parseBeacon(body), url + "/aab9"
	}

	return nil, ""
}

func WebRequest(timeout int, url string) (bool, string) {

	client := utils.GetConfiguredClient(timeout)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, ""
	}

	req.Header.Add("Connection", "close")
	req.Close = true
	resp, err := client.Do(req)

	// To skip response processing
	if resp != nil {
		io.Copy(ioutil.Discard, resp.Body)
		resp.Body.Close()
	}
	if err != nil {
		return false, ""
	}

	return true, fmt.Sprintf("%d/%d", resp.StatusCode, resp.ContentLength)
}

func GetTeamServerCertificate(host string) string {
	certs := utils.NewCert(host)
	return certs.Issuer
}

func CheckJARM(host string) string {
	ip := strings.Split(host, ":")[0]

	return utils.JarmFingerprint(utils.Target{
		Host: ip,
		Port: 50050,
	}).Hash
}

func Launch(request utils.ScanRequest) (response utils.ScanResponse) {

	targets := request.Targets
	settings := request.Setting

	sort := &utils.Sorter{}
	sort.Init()
	svc := utils.LoadDynamoDBService()

	start := time.Now()

	portChannel := make(chan string)
	httpChannel := make(chan string)
	httpsChannel := make(chan string)
	beaconChannel := make(chan string)
	outputChannel := make(chan string)

	beaconStructChannel := make(chan utils.CobaltStrikeBeaconStruct)
	var BeaconConfigs []utils.CobaltStrikeBeaconStruct

	batchSize := 20

	// Port workers
	var portWG sync.WaitGroup
	for i := 0; i < int(settings.Concurrency*37/100); i++ {
		portWG.Add(1)
		go func() {
			for srv := range portChannel {
				conn, err := net.DialTimeout("tcp", srv, time.Millisecond*time.Duration(settings.PortDelay))
				if err != nil {
					continue
				}
				conn.Close()
				httpChannel <- srv
				outputChannel <- "Service|" + srv
			}
			portWG.Done()
		}()
	}

	// HTTP workers
	var httpWG sync.WaitGroup
	for i := 0; i < int(settings.Concurrency*28/100); i++ {
		httpWG.Add(1)

		go func() {
			for host := range httpChannel {
				response.Ports += 1
				if utils.CheckPort(host, 50050) {
					outputChannel <- "Certificate|" + host + "|" + GetTeamServerCertificate(host)
					outputChannel <- "Jarm|" + host + "|" + CheckJARM(host)
					continue
				}

				url := "http://" + host
				ok, resp := WebRequest(settings.HttpDelay, url)
				if ok {
					response.Services += 1
					if resp == "404/0" {
						beaconChannel <- url
					}
					outputChannel <- "Response|" + url + "|" + resp
					continue
				}
				httpsChannel <- host
			}
			httpWG.Done()
		}()
	}

	// HTTPS workers
	var httpsWG sync.WaitGroup
	for i := 0; i < int(settings.Concurrency*10/100); i++ {
		httpsWG.Add(1)
		go func() {
			for host := range httpsChannel {
				url := "https://" + host
				ok, resp := WebRequest(settings.HttpDelay, url)
				if ok {
					response.Services += 1
					if resp == "404/0" {
						beaconChannel <- url
					}
					outputChannel <- "Response|" + url + "|" + resp
					continue
				}
			}
			httpsWG.Done()
		}()
	}

	// Beacon workers
	var beaconWG sync.WaitGroup
	for i := 0; i < int(settings.Concurrency*25/100); i++ {
		beaconWG.Add(1)

		go func() {
			for url := range beaconChannel {
				beacon, beaconUri := GetBeaconConfig(settings.HttpBeaconDelay, url)
				if beacon != nil {
					response.Beacons += 1

					beaconStructChannel <- utils.CobaltStrikeBeaconStruct{
						Uri:          beaconUri,
						BeaconConfig: beacon,
					}
					outputChannel <- "Beacon|" + beaconUri
				}
			}
			beaconWG.Done()
		}()
	}

	var beaconStructWG sync.WaitGroup
	beaconStructWG.Add(1)
	go func() {
		for b := range beaconStructChannel {
			BeaconConfigs = append(BeaconConfigs, b)
		}
		beaconStructWG.Done()
	}()

	// Output worker
	var outputWG sync.WaitGroup
	for i := 0; i < int(settings.Concurrency*5/100); i++ {
		outputWG.Add(1)
		go func() {
			for o := range outputChannel {
				// pointer
				utils.ValidateOutput(o, sort)
			}
			outputWG.Done()
		}()
	}

	go func() {
		portWG.Wait()
		close(httpChannel)
	}()

	go func() {
		httpWG.Wait()
		close(httpsChannel)
	}()

	go func() {
		httpsWG.Wait()
		close(beaconChannel)
	}()

	go func() {
		beaconWG.Wait()
		close(beaconStructChannel)
		close(outputChannel)
	}()

	for _, ip := range targets.Ips {
		// init all ips
		sort.Responses[ip] = make(map[string]string)
		for _, port := range settings.Ports {
			portChannel <- fmt.Sprintf("%s:%d", ip, port)
		}
	}

	close(portChannel)
	beaconStructWG.Wait()
	outputWG.Wait()

	cst := utils.Voter(sort.Sort())
	length_T := len(cst)

	// Write the Target Configs
	for i := 0; i < length_T; i += batchSize {
		utils.WriteBatchTarget(svc, cst[i:utils.Min(i+batchSize, length_T)])
	}

	// Write the Beacon Configs
	length_B := len(BeaconConfigs)
	for i := 0; i < length_B; i += batchSize {
		utils.WriteBatchBeacons(svc, BeaconConfigs[i:utils.Min(i+batchSize, length_B)])
	}

	response.Time = fmt.Sprintf("%s", time.Now().Sub(start))
	response.PacketId = request.PacketId
	return response
}
