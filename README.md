# Description

The Pointer was developed for hunting and mapping Cobalt Strike servers exposed to the Internet. The tool includes the complete methodology for identifying Cobalt Strike servers. It is intended to speed up the process of detecting Cobalt Strike servers among a large number of potential targets in a short period of time.

# Disclaimer

The tool is in beta stage (testing in progress). A detailed overview of main components of the tool is described in the blog post prepared by Pavel Shabarkin and Michael Koczwara: [https://medium.com/@shabarkin/pointer-hunting-cobalt-strike-globally-a334ac50619a](https://medium.com/@shabarkin/pointer-hunting-cobalt-strike-globally-a334ac50619a)

I recommend using a separate AWS account for scanning and mapping Cobalt Strike servers.

# Install

If you have Go installed and configured (i.e. with `$GOPATH/bin` in your `$PATH`):

```
sudo go get -u github.com/shabarkin/pointer
```
or 
```
sudo git clone https://github.com/shabarkin/pointer.git
```
```
sudo go build .
```

# Basic Usage

The tool is developed and largely based on AWS SQS, Lambda and DynamoDB services. Pointer has a `configure` subcommand for automatic deployment of IAM, Lambda, SQS, DynamoDB, and Autoscaling services. To configure all of these services Pointer needs permissions to manage them, for simplicity we recommend providing Pointer with an administrative type account that includes all of the necessary permissions. That's why I recommend using a separate AWS account, especially if you use other Lambda functions within your AWS account.

## Creating an AWS user account in the AWS Console

### Instruction

1. AWS Console → IAM → User groups → Create Group → 1. Provide name of the group 2. Attach permission policy "AdministratorAccess". 
2. AWS Console → IAM → Users → Add Users → 1. Provide name of the user 2. Select "Access key - Programmatic access" → Add user to group (What we've created) 

### Video

[![Alt text](https://img.youtube.com/vi/YgBc96u0hM4/0.jpg)](https://www.youtube.com/watch?v=YgBc96u0hM4)

## Setting up credentials

**WARNING:** The configuration action requires the `function.zip` file to be located within the directory, where a user runs the command. The `function.zip` file is actually a "Pointer server" compiled and zipped to the format required for a Lambda deployment. 

![Screenshot 2021-09-23 at 11.00.10.png](_img/Screenshot_2021-09-23_at_11.00.10.png)

Pointer has the `configure` subcommand with two options:

1. Automatic deployment of AWS environment where you need to provide AWS credentials of the admin account: 

```bash
./pointer configure -aws_access_key_id AKIA85CEHPO3GLIABKZD -aws_secret_access_key LW3bDF8xJvzGgArqMo0h4kuCYsnubU23kGICGp/p
```

![Screenshot 2021-09-23 at 10.13.26.png](_img/Screenshot_2021-09-23_at_10.13.26.png)

2. Cleaning of the configured AWS environment 

```bash
./pointer configure -clear
```

![Screenshot 2021-09-23 at 10.13.59.png](_img/Screenshot_2021-09-23_at_10.13.59.png)

**WARNING:** It creates `.env` file, which is loaded to global variables each time you call subcommands.

![Screenshot 2021-09-23 at 10.14.17.png](_img/Screenshot_2021-09-23_at_10.14.17.png)

## Scanning

The `scan` subcommand includes 3 options: 1. launch the scan 2. stop the scan 3. check the status of the scan

### Launch the scan

The Pointer tool parses the local json file (`ips.json`) with a list of IPs, optimally splits them into packets (10 IPs), and then adds the packets to be processed to the SQS queue: 

```bash
./pointer scan -targets ips.json
```

The format of the `ips.json` file:

```json
{
    "ips": [
        "1.116.119.120",
        "1.116.158.193",
        "1.116.186.39",
        "1.116.207.171",
        "1.116.246.188",
	...
    ]
}
```

![Screenshot 2021-09-23 at 10.30.06.png](_img/Screenshot_2021-09-23_at_10.30.06.png)


### View status of the scan

The Pointer retrieves information about the SQS Queue, how many packages are in the queue and waiting to be scanned, and how many packages are being processed at the current moment:

```bash
./pointer scan -status
```

![Screenshot 2021-09-23 at 10.31.12.png](_img/Screenshot_2021-09-23_at_10.31.12.png)

### Stop the scan

To stop the scan, Pointer purges all the messages (packages) from the SQS Queue: 

```bash
./pointer scan -stop
```

![Screenshot 2021-09-23 at 10.31.59.png](_img/Screenshot_2021-09-23_at_10.31.59.png)

## Dumping

All the scan results are stored in DynamoDB tables: 1. Targets, 2. Beacons. 

```bash
./pointer dump -outfile 23.09.2021
```

![Screenshot 2021-09-23 at 10.43.03.png](_img/Screenshot_2021-09-23_at_10.43.03.png)

The only controllable parameter is the suffix for the output file, all the dumped results are saved to the to the `.csv`, and `.json` files in the `results` folder (current directory):

![Screenshot 2021-09-23 at 10.51.19.png](_img/Screenshot_2021-09-23_at_10.51.19.png)

**WARNING:** After result dumping, Pointer clears the DynamoDB tables, so you won't have a backup of the results obtained, only the one saved in the `results` folder.

**The data samples you may find here:** [https://docs.google.com/spreadsheets/d/1akSzGDq8ddn97rNfr7BS0w2HcoR52ircFaSMh-OEjTU/edit#gid=311496774](https://docs.google.com/spreadsheets/d/1akSzGDq8ddn97rNfr7BS0w2HcoR52ircFaSMh-OEjTU/edit#gid=311496774)

## Demo Video

[![Alt text](https://img.youtube.com/vi/ToXfFPldGVc/0.jpg)](https://www.youtube.com/watch?v=ToXfFPldGVc)
