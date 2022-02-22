package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/shabarkin/pointer_server/beacon"
	"github.com/shabarkin/pointer_server/utils"
)

// ADD: exit program if can't load targets

func HandleLambdaEvent(event utils.ScanRequest) (utils.ScanResponse, error) {
	result := beacon.Launch(event)
	return result, nil
}

func SQSLambdaHandlerEvent(ctx context.Context, sqsEvent events.SQSEvent) error {

	for _, message := range sqsEvent.Records {

		event := &utils.ScanRequest{}
		err := json.Unmarshal([]byte(message.Body), event)
		if err != nil {
			fmt.Println("Error of marshaling")
		}

		result := beacon.Launch(*event)

		svc := utils.LoadDynamoDBService()
		utils.WriteResponse(svc, result)
	}

	return nil
}

func main() {
	lambda.Start(SQSLambdaHandlerEvent)
}
