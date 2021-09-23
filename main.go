package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/shabarkin/pointer_dev/utils"
)

var PointerHelper string = `Usage:
pointer [command]

Available Commands:
  configure			Saves AWS credentials to .env file for later authentication and prepares the cloud environment to be ready to the scan
  scan				Scans targets identifying, mapping and parsing the Cobalt Strike servers
  dump				Dump the scan results to the local .csv and .json file, checks the scan status, and clears out the DynamoDb table to be ready for the new scan
  
Flags:
  -h				Pointer Helper
`

var PointerConfigure string = `Usage:
pointer configure [command]
	  
Flags:
  -aws_access_key_id			Specify AWS Access Key for wanted account.
  -aws_secret_access_key		Specify AWS Secret Access Key for wanted account.
  -clear				Clear the cloud environment
  
Example:
  ./pointer configure -aws_access_key_id AKIA85CEHPO3GLIABKZD -aws_secret_access_key LW3bDF8xJvzGgArqMo0h4kuCYsnubU23kGICGp/p
  ./pointer configure -clear
`

var PointerScanHelper string = `Usage:
pointer scan [command]
	  
Flags:
  -targets		Filename with the list of targets (.json extension)
  -stop			Stops the scan
  -status		Shows the status of the scan

Example:
  ./pointer scan -targets ips.json
  ./pointer scan -stop
  ./pointer scan -status
`

var PointerDumpHelper string = `Usage:
pointer dump [command]
	  
Flags:
  -outfile		Is a file suffix: ('-outfile 1' will be a targets1.csv)

Example:
  ./pointer dump -outfile 1
`

var Configuration *flag.FlagSet = flag.NewFlagSet("configure", flag.ExitOnError)
var AWS_access_key_id *string = Configuration.String("aws_access_key_id", "", "")
var AWS_secret_access_key *string = Configuration.String("aws_secret_access_key", "", "")
var Clear *bool = Configuration.Bool("clear", false, "")

var Scan *flag.FlagSet = flag.NewFlagSet("scan", flag.ExitOnError)
var Targets *string = Scan.String("targets", "ips.json", "")
var Stop *bool = Scan.Bool("stop", false, "")
var Status *bool = Scan.Bool("status", false, "")

var Dump *flag.FlagSet = flag.NewFlagSet("dump", flag.ExitOnError)
var OutFilePrefix *string = Dump.String("outfile", "", "")

func main() {

	Configuration.Usage = func() {
		fmt.Fprintf(os.Stderr, PointerConfigure)
	}
	Scan.Usage = func() {
		fmt.Fprintf(os.Stderr, PointerScanHelper)
	}
	Dump.Usage = func() {
		fmt.Fprintf(os.Stderr, PointerDumpHelper)
	}
	if len(os.Args) < 2 {
		fmt.Println(PointerHelper)
		os.Exit(1)
	}
	switch os.Args[1] {

	case "configure":
		Configuration.Parse(os.Args[2:])

		if *Clear {
			utils.LoadEnv()
			if utils.ServicesAvailability(false) {
				utils.ClearCloudEnvironment()
				fmt.Println(utils.Green("[Message]:"), "Cloud Environment is cleaned up")
				os.Exit(1)
			}
		} else {
			utils.CreateAWScredentialsFile(AWS_access_key_id, AWS_secret_access_key)
			utils.LoadEnv()
			if utils.ServicesAvailability(false) {
				fmt.Println(utils.Green("[Message]:"), "Cloud Environment is already setup")
				os.Exit(1)
			}

			utils.AutoDeploymentCLI()

			if !utils.ServicesAvailability(true) {
				fmt.Println(utils.Green("[Message]:"), "Cloud Environment has not been setup, try again ... ")
				os.Exit(1)
			}

			fmt.Println(utils.Green("[Message]:"), "Cloud is successfully setup")
		}

	case "scan":
		Scan.Parse(os.Args[2:])
		utils.LoadEnv()

		if utils.ServicesAvailability(true) {
			if *Status {
				utils.GetScanStatus(true)
				os.Exit(1)
			}

			if *Stop {
				utils.StopScan()
				os.Exit(1)
			}

			requests := utils.BatchTargets(*Targets)
			utils.Launcher(requests)
		}

	case "dump":
		Dump.Parse(os.Args[2:])
		utils.LoadEnv()

		if utils.ServicesAvailability(true) {

			if utils.GetScanStatus(false) {
				//Dump the Target table
				targets := utils.ScanDynamoForTargets()
				fmt.Println(utils.Green("[Message]:"), "Parsed Targets:", len(targets))
				utils.WriteCobaltStrikeTargetsCSV("targets"+*OutFilePrefix+".csv", targets)
				utils.WriteCobaltStrikeTargets("targets"+*OutFilePrefix+".json", targets)

				// Dump the Beacons table
				beacons := utils.ScanDynamoForBeacons()
				fmt.Println(utils.Green("[Message]:"), "Parsed Beacons:", len(beacons))
				utils.WriteCobaltStrikeBeaconsCSV("beacons"+*OutFilePrefix+".csv", beacons)
				utils.WriteCobaltStrikeBeacons("beacons"+*OutFilePrefix+".json", beacons)

				utils.ClearDatabases()
			} else {
				fmt.Println(utils.Green("[Message]:"), "Scan in progress, wait for finishing or stop the scan")
			}
		}

	default:
		fmt.Println(PointerHelper)
		os.Exit(1)
	}
}
