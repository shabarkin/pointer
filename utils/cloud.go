package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/applicationautoscaling"
	"github.com/pkg/errors"
)

func getPayload(request ScanRequest) string {
	payload, err := json.Marshal(request)
	if err != nil {
		fmt.Println(Yellow("[Err]:"), "Can't marshal the ScanRequest:", err)
		return ""
	}
	return string(payload)
}

func LoadDynamoDBService() *dynamodb.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalln(Yellow("[Err]: ") + "Unable to load SDK config")
	}
	return dynamodb.NewFromConfig(cfg)
}

func AutoDeploy() {

	// General configuration to work with AWS
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalln(Yellow("[Err]: ") + "Unable to load SDK config")
	}

	// Creating the Service Role for a lambda function and attaching the required policies
	svc_iam := iam.NewFromConfig(cfg)
	svc_iam.CreateRole(context.TODO(), &iam.CreateRoleInput{
		RoleName:                 aws.String(IAMRoleName),
		AssumeRolePolicyDocument: aws.String(`{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}`),
	})

	svc_iam.AttachRolePolicy(context.TODO(), &iam.AttachRolePolicyInput{
		RoleName:  aws.String(IAMRoleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
	})

	svc_iam.AttachRolePolicy(context.TODO(), &iam.AttachRolePolicyInput{
		RoleName:  aws.String(IAMRoleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"),
	})

	svc_iam.AttachRolePolicy(context.TODO(), &iam.AttachRolePolicyInput{
		RoleName:  aws.String(IAMRoleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonSQSFullAccess"),
	})

	time.Sleep(3000 * time.Millisecond)
	// Deploying the lambda function from the local function.zip file
	GetRoleOutput, _ := svc_iam.GetRole(context.TODO(), &iam.GetRoleInput{
		RoleName: aws.String(IAMRoleName),
	})

	svc_lambda := lambda.NewFromConfig(cfg)

	data, err := ioutil.ReadFile("function.zip")
	if err != nil {
		fmt.Println(Yellow("[Err]:"), err)
		os.Exit(1)
	}

	svc_lambda.CreateFunction(context.TODO(), &lambda.CreateFunctionInput{
		FunctionName: aws.String(LambdaFunction),
		Handler:      aws.String("main"),
		Runtime:      lambdaTypes.RuntimeGo1x,
		Role:         GetRoleOutput.Role.Arn,
		MemorySize:   aws.Int32(LambdaMemory),
		Timeout:      aws.Int32(LambdaTimeout),
		Code: &lambdaTypes.FunctionCode{
			ZipFile: data,
		},
	})

	for i := 0; i < 9; i++ {
		_, err = svc_lambda.GetFunction(context.TODO(), &lambda.GetFunctionInput{
			FunctionName: aws.String(LambdaFunction),
		})

		if err != nil {
			fmt.Println(Yellow("[Err]:"), "Function is not available yet")
			time.Sleep(5000 * time.Millisecond)
			continue
		}
		break
	}

	_, errLambda := svc_lambda.GetFunction(context.TODO(), &lambda.GetFunctionInput{
		FunctionName: aws.String(LambdaFunction),
	})

	if errLambda != nil {
		fmt.Println(Yellow("[Err]:"), "Run the configure command again,the Lambda function was failed to be configured")
		time.Sleep(5000 * time.Millisecond)
		os.Exit(1)
	}

	// Creating the SQS Queue
	svc_sqs := sqs.NewFromConfig(cfg)

	svc_sqs.CreateQueue(context.TODO(), &sqs.CreateQueueInput{
		QueueName: aws.String(SQSQueue),
		Attributes: map[string]string{
			"MessageRetentionPeriod": "600", // 10 minutes
			"VisibilityTimeout":      "120", // 2  minutes
		},
	})

	for i := 0; i < 9; i++ {
		_, err = svc_sqs.GetQueueUrl(context.TODO(), &sqs.GetQueueUrlInput{
			QueueName: aws.String(SQSQueue),
		})

		if err != nil {
			fmt.Println(Yellow("[Err]:"), "Queue is not available yet")
			time.Sleep(5000 * time.Millisecond)
			continue
		}
		break
	}

	// Attaching the SQS trigger to the lambda function
	SQSUri, errSQS := svc_sqs.GetQueueUrl(context.TODO(), &sqs.GetQueueUrlInput{
		QueueName: aws.String(SQSQueue),
	})

	if errSQS != nil {
		fmt.Println(Yellow("[Err]:"), "Run the configure command again, the SQS was failed to be configured")
		time.Sleep(5000 * time.Millisecond)
		os.Exit(1)
	}

	SQSAttributes, err := svc_sqs.GetQueueAttributes(context.TODO(), &sqs.GetQueueAttributesInput{
		QueueUrl: SQSUri.QueueUrl,
		AttributeNames: []sqsTypes.QueueAttributeName{
			"QueueArn",
		},
	})

	_, err = svc_lambda.CreateEventSourceMapping(context.TODO(), &lambda.CreateEventSourceMappingInput{
		BatchSize:                      aws.Int32(1),
		FunctionName:                   aws.String(LambdaFunction),
		MaximumBatchingWindowInSeconds: aws.Int32(10),
		EventSourceArn:                 aws.String(SQSAttributes.Attributes["QueueArn"]),
	})

	if err != nil {
		fmt.Println(Yellow("[Err]:"), err.Error())
	}

	// Create DynamoDB Tables
	svc_dynamo := dynamodb.NewFromConfig(cfg)

	// Create Targets table
	svc_dynamo.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(TableTargets),
		AttributeDefinitions: []dynamodbTypes.AttributeDefinition{
			{
				AttributeName: aws.String("Ip"),
				AttributeType: dynamodbTypes.ScalarAttributeTypeS,
			},
		},
		KeySchema: []dynamodbTypes.KeySchemaElement{
			{
				AttributeName: aws.String("Ip"),
				KeyType:       dynamodbTypes.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &dynamodbTypes.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(10),
		},
	})

	// Create Beacons table
	svc_dynamo.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(TableBeacons),
		AttributeDefinitions: []dynamodbTypes.AttributeDefinition{
			{
				AttributeName: aws.String("Uri"),
				AttributeType: dynamodbTypes.ScalarAttributeTypeS,
			},
		},
		KeySchema: []dynamodbTypes.KeySchemaElement{
			{
				AttributeName: aws.String("Uri"),
				KeyType:       dynamodbTypes.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &dynamodbTypes.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(10),
		},
	})

	// Create Responses table
	svc_dynamo.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(TableResponses),
		AttributeDefinitions: []dynamodbTypes.AttributeDefinition{
			{
				AttributeName: aws.String("PacketId"),
				AttributeType: dynamodbTypes.ScalarAttributeTypeN,
			},
		},
		KeySchema: []dynamodbTypes.KeySchemaElement{
			{
				AttributeName: aws.String("PacketId"),
				KeyType:       dynamodbTypes.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &dynamodbTypes.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(10),
		},
	})

	waitForTable(context.TODO(), svc_dynamo, TableTargets)
	waitForTable(context.TODO(), svc_dynamo, TableBeacons)
	waitForTable(context.TODO(), svc_dynamo, TableResponses)

	//
	//
	// Setup the autoscaling policy
	mySession := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")},
	))

	// Create a ApplicationAutoScaling client from just a session.
	svc_applicationautoscaling := applicationautoscaling.New(mySession)

	// Create autoscaling for the Targets table
	svc_applicationautoscaling.RegisterScalableTarget(&applicationautoscaling.RegisterScalableTargetInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableTargets),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		MinCapacity:       aws.Int64(10),
		MaxCapacity:       aws.Int64(20),
	})

	// Create autoscaling for the Beacons table
	svc_applicationautoscaling.RegisterScalableTarget(&applicationautoscaling.RegisterScalableTargetInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableBeacons),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		MinCapacity:       aws.Int64(10),
		MaxCapacity:       aws.Int64(20),
	})
	// Create autoscaling for the Responses table
	svc_applicationautoscaling.RegisterScalableTarget(&applicationautoscaling.RegisterScalableTargetInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableResponses),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		MinCapacity:       aws.Int64(10),
		MaxCapacity:       aws.Int64(20),
	})

	time.Sleep(3000 * time.Millisecond)

	// Configure policy for autoscaling for the Targets table
	svc_applicationautoscaling.PutScalingPolicy(&applicationautoscaling.PutScalingPolicyInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableTargets),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		PolicyName:        aws.String("MyScalingPolicy"),
		PolicyType:        aws.String("TargetTrackingScaling"),
		TargetTrackingScalingPolicyConfiguration: &applicationautoscaling.TargetTrackingScalingPolicyConfiguration{
			PredefinedMetricSpecification: &applicationautoscaling.PredefinedMetricSpecification{
				PredefinedMetricType: aws.String("DynamoDBWriteCapacityUtilization"),
			},
			ScaleOutCooldown: aws.Int64(60),
			ScaleInCooldown:  aws.Int64(60),
			TargetValue:      aws.Float64(50.0),
		},
	})

	svc_applicationautoscaling.PutScalingPolicy(&applicationautoscaling.PutScalingPolicyInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableBeacons),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		PolicyName:        aws.String("MyScalingPolicy"),
		PolicyType:        aws.String("TargetTrackingScaling"),
		TargetTrackingScalingPolicyConfiguration: &applicationautoscaling.TargetTrackingScalingPolicyConfiguration{
			PredefinedMetricSpecification: &applicationautoscaling.PredefinedMetricSpecification{
				PredefinedMetricType: aws.String("DynamoDBWriteCapacityUtilization"),
			},
			ScaleOutCooldown: aws.Int64(60),
			ScaleInCooldown:  aws.Int64(60),
			TargetValue:      aws.Float64(50.0),
		},
	})

	svc_applicationautoscaling.PutScalingPolicy(&applicationautoscaling.PutScalingPolicyInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableResponses),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		PolicyName:        aws.String("MyScalingPolicy"),
		PolicyType:        aws.String("TargetTrackingScaling"),
		TargetTrackingScalingPolicyConfiguration: &applicationautoscaling.TargetTrackingScalingPolicyConfiguration{
			PredefinedMetricSpecification: &applicationautoscaling.PredefinedMetricSpecification{
				PredefinedMetricType: aws.String("DynamoDBWriteCapacityUtilization"),
			},
			ScaleOutCooldown: aws.Int64(60),
			ScaleInCooldown:  aws.Int64(60),
			TargetValue:      aws.Float64(50.0),
		},
	})
}

func waitForTable(ctx context.Context, db *dynamodb.Client, tn string) error {
	w := dynamodb.NewTableExistsWaiter(db)
	err := w.Wait(ctx,
		&dynamodb.DescribeTableInput{
			TableName: aws.String(tn),
		},
		2*time.Minute,
		func(o *dynamodb.TableExistsWaiterOptions) {
			o.MaxDelay = 2 * time.Second
			o.MinDelay = 2 * time.Second
		})
	if err != nil {
		return errors.Wrap(err, Yellow("[Err]: ")+"timed out while waiting for table to become active")
	}

	return err
}

func SendMessageSQS(svc *sqs.Client, payload string) {

	SQSUri, err := svc.GetQueueUrl(context.TODO(), &sqs.GetQueueUrlInput{
		QueueName: aws.String(SQSQueue),
	})
	if err != nil {
		fmt.Println(Yellow("[Err]: ") + "SQS Queue is not available ...")
	}

	input := &sqs.SendMessageInput{
		QueueUrl:    SQSUri.QueueUrl,
		MessageBody: aws.String(payload),
	}

	_, err = svc.SendMessage(context.TODO(), input)

	if err != nil {
		log.Fatalf(Yellow("[Err]: ")+"Got error invoking lambda: %s", err)
	}
}

func Launcher(requests []ScanRequest) {

	fmt.Println(Green("Scan configurations:"))
	fmt.Println("Packets:            ", len(requests))
	fmt.Println("Packet Size:        ", BatchSize)
	fmt.Println("Scan Concurrency:   ", requests[0].Setting.Concurrency)
	fmt.Println("Scan Port Delay:    ", requests[0].Setting.PortDelay)
	fmt.Println("Scan Http Delay:    ", requests[0].Setting.HttpDelay)
	fmt.Println("Scan Beacon Delay:  ", requests[0].Setting.HttpBeaconDelay)

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalln(Yellow("[Err]: ") + "Unable to load SDK config")
	}
	svc := sqs.NewFromConfig(cfg)

	for i := 0; i < len(requests); i++ {
		SendMessageSQS(svc, getPayload(requests[i]))
	}
}

func ScanDynamoForResponses() (items []ScanResponse) {
	svc := LoadDynamoDBService()

	params := &dynamodb.ScanInput{
		TableName: aws.String(TableResponses),
	}

	result, err := svc.Scan(context.TODO(), params)
	if err != nil {
		log.Fatalf(Yellow("[Err]: ")+"Query API call failed: %s", err)
	}

	for _, i := range result.Items {
		item := &ScanResponse{}

		err = attributevalue.UnmarshalMap(i, item)

		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Got error unmarshalling: %s", err)
		}

		items = append(items, *item)
	}

	return items
}

func ScanDynamoForBeacons() (items []CobaltStrikeBeaconStruct) {
	svc := LoadDynamoDBService()

	params := &dynamodb.ScanInput{
		TableName: aws.String(TableBeacons),
	}

	result, err := svc.Scan(context.TODO(), params)
	if err != nil {
		log.Fatalf(Yellow("[Err]: ")+"Query API call failed: %s", err)
	}
	for _, i := range result.Items {
		item := &CobaltStrikeBeaconStruct{}

		err = attributevalue.UnmarshalMap(i, item)

		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Got error unmarshalling: %s", err)
		}

		items = append(items, *item)
	}

	///
	/// Loop for gettting next pages
	///

	key := result.LastEvaluatedKey
	for key != nil {
		params := &dynamodb.ScanInput{
			TableName:         aws.String(TableBeacons),
			ExclusiveStartKey: key,
		}

		result, err := svc.Scan(context.TODO(), params)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Query API call failed: %s", err)
		}
		for _, i := range result.Items {
			item := &CobaltStrikeBeaconStruct{}

			err = attributevalue.UnmarshalMap(i, item)

			if err != nil {
				log.Fatalf(Yellow("[Err]: ")+"Got error unmarshalling: %s", err)
			}

			items = append(items, *item)
		}
		key = result.LastEvaluatedKey
	}

	return items
}

func ScanDynamoForTargets() (items []CobaltStrikeStruct) {
	svc := LoadDynamoDBService()

	params := &dynamodb.ScanInput{
		TableName: aws.String(TableTargets),
	}

	result, err := svc.Scan(context.TODO(), params)
	if err != nil {
		log.Fatalf(Yellow("[Err]: ")+"Query API call failed: %s", err)
	}

	for _, i := range result.Items {
		item := &CobaltStrikeStruct{}

		err = attributevalue.UnmarshalMap(i, item)

		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Got error unmarshalling: %s", err)
		}

		items = append(items, *item)
	}

	//
	//
	//

	key := result.LastEvaluatedKey
	for key != nil {
		params := &dynamodb.ScanInput{
			TableName:         aws.String(TableTargets),
			ExclusiveStartKey: key,
		}

		result, err := svc.Scan(context.TODO(), params)
		if err != nil {
			log.Fatalf(Yellow("[Err]: ")+"Query API call failed: %s", err)
		}
		for _, i := range result.Items {
			item := &CobaltStrikeStruct{}

			err = attributevalue.UnmarshalMap(i, item)

			if err != nil {
				log.Fatalf(Yellow("[Err]: ")+"Got error unmarshalling: %s", err)
			}

			items = append(items, *item)
		}
		key = result.LastEvaluatedKey
	}

	return items
}

func AutoDeploymentCLI() {

	if CheckInitialPermissions() {
		fmt.Println(Green("[Message]:"), "Credentials are successfully installed")
	} else {
		fmt.Println(Yellow("[Err]:"), "The provided account does not has attached AdministratorAccess policy")
		os.Exit(1)
	}

	AutoDeploy()
	time.Sleep(3000 * time.Millisecond)
}

func CheckInitialPermissions() bool {

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalln(Yellow("[Err]: ") + "Unable to load SDK config")
	}

	svc_iam := iam.NewFromConfig(cfg)

	ListAttachedGroupPoliciesOut, err := svc_iam.ListAttachedGroupPolicies(context.TODO(), &iam.ListAttachedGroupPoliciesInput{
		GroupName: aws.String("admin"),
	})

	if err != nil {
		fmt.Println(Yellow("[Err]:"), "ListAttachedGroupPolicies action is not completed, probably this account has no rights to request this action")
		os.Exit(1)
	}

	for _, Policy := range ListAttachedGroupPoliciesOut.AttachedPolicies {
		if *Policy.PolicyArn == "arn:aws:iam::aws:policy/AdministratorAccess" {
			return true
		}
	}
	return false
}

func ClearDatabases() {
	svc_dynamo := LoadDynamoDBService()

	// Deleting tables
	svc_dynamo.DeleteTable(context.TODO(), &dynamodb.DeleteTableInput{
		TableName: aws.String(TableTargets),
	})
	svc_dynamo.DeleteTable(context.TODO(), &dynamodb.DeleteTableInput{
		TableName: aws.String(TableBeacons),
	})
	svc_dynamo.DeleteTable(context.TODO(), &dynamodb.DeleteTableInput{
		TableName: aws.String(TableResponses),
	})

	time.Sleep(8000 * time.Millisecond)

	// Create Targets table
	svc_dynamo.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(TableTargets),
		AttributeDefinitions: []dynamodbTypes.AttributeDefinition{
			{
				AttributeName: aws.String("Ip"),
				AttributeType: dynamodbTypes.ScalarAttributeTypeS,
			},
		},
		KeySchema: []dynamodbTypes.KeySchemaElement{
			{
				AttributeName: aws.String("Ip"),
				KeyType:       dynamodbTypes.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &dynamodbTypes.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(10),
		},
	})

	// Create Beacons table
	svc_dynamo.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(TableBeacons),
		AttributeDefinitions: []dynamodbTypes.AttributeDefinition{
			{
				AttributeName: aws.String("Uri"),
				AttributeType: dynamodbTypes.ScalarAttributeTypeS,
			},
		},
		KeySchema: []dynamodbTypes.KeySchemaElement{
			{
				AttributeName: aws.String("Uri"),
				KeyType:       dynamodbTypes.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &dynamodbTypes.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(10),
		},
	})

	// Create Responses table
	svc_dynamo.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(TableResponses),
		AttributeDefinitions: []dynamodbTypes.AttributeDefinition{
			{
				AttributeName: aws.String("PacketId"),
				AttributeType: dynamodbTypes.ScalarAttributeTypeN,
			},
		},
		KeySchema: []dynamodbTypes.KeySchemaElement{
			{
				AttributeName: aws.String("PacketId"),
				KeyType:       dynamodbTypes.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &dynamodbTypes.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(10),
			WriteCapacityUnits: aws.Int64(10),
		},
	})

	waitForTable(context.TODO(), svc_dynamo, TableTargets)
	waitForTable(context.TODO(), svc_dynamo, TableBeacons)
	waitForTable(context.TODO(), svc_dynamo, TableResponses)

	//
	//
	// Setup the autoscaling policy
	mySession := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")},
	))

	// Create a ApplicationAutoScaling client from just a session.
	svc_applicationautoscaling := applicationautoscaling.New(mySession)

	// Create autoscaling for the Targets table
	svc_applicationautoscaling.RegisterScalableTarget(&applicationautoscaling.RegisterScalableTargetInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableTargets),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		MinCapacity:       aws.Int64(10),
		MaxCapacity:       aws.Int64(20),
	})

	// Create autoscaling for the Beacons table
	svc_applicationautoscaling.RegisterScalableTarget(&applicationautoscaling.RegisterScalableTargetInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableBeacons),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		MinCapacity:       aws.Int64(10),
		MaxCapacity:       aws.Int64(20),
	})
	// Create autoscaling for the Responses table
	svc_applicationautoscaling.RegisterScalableTarget(&applicationautoscaling.RegisterScalableTargetInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableResponses),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		MinCapacity:       aws.Int64(10),
		MaxCapacity:       aws.Int64(20),
	})

	time.Sleep(3000 * time.Millisecond)

	// Configure policy for autoscaling for the Targets table
	svc_applicationautoscaling.PutScalingPolicy(&applicationautoscaling.PutScalingPolicyInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableTargets),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		PolicyName:        aws.String("MyScalingPolicy"),
		PolicyType:        aws.String("TargetTrackingScaling"),
		TargetTrackingScalingPolicyConfiguration: &applicationautoscaling.TargetTrackingScalingPolicyConfiguration{
			PredefinedMetricSpecification: &applicationautoscaling.PredefinedMetricSpecification{
				PredefinedMetricType: aws.String("DynamoDBWriteCapacityUtilization"),
			},
			ScaleOutCooldown: aws.Int64(60),
			ScaleInCooldown:  aws.Int64(60),
			TargetValue:      aws.Float64(50.0),
		},
	})

	svc_applicationautoscaling.PutScalingPolicy(&applicationautoscaling.PutScalingPolicyInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableBeacons),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		PolicyName:        aws.String("MyScalingPolicy"),
		PolicyType:        aws.String("TargetTrackingScaling"),
		TargetTrackingScalingPolicyConfiguration: &applicationautoscaling.TargetTrackingScalingPolicyConfiguration{
			PredefinedMetricSpecification: &applicationautoscaling.PredefinedMetricSpecification{
				PredefinedMetricType: aws.String("DynamoDBWriteCapacityUtilization"),
			},
			ScaleOutCooldown: aws.Int64(60),
			ScaleInCooldown:  aws.Int64(60),
			TargetValue:      aws.Float64(50.0),
		},
	})

	svc_applicationautoscaling.PutScalingPolicy(&applicationautoscaling.PutScalingPolicyInput{
		ServiceNamespace:  aws.String("dynamodb"),
		ResourceId:        aws.String("table/" + TableResponses),
		ScalableDimension: aws.String("dynamodb:table:WriteCapacityUnits"),
		PolicyName:        aws.String("MyScalingPolicy"),
		PolicyType:        aws.String("TargetTrackingScaling"),
		TargetTrackingScalingPolicyConfiguration: &applicationautoscaling.TargetTrackingScalingPolicyConfiguration{
			PredefinedMetricSpecification: &applicationautoscaling.PredefinedMetricSpecification{
				PredefinedMetricType: aws.String("DynamoDBWriteCapacityUtilization"),
			},
			ScaleOutCooldown: aws.Int64(60),
			ScaleInCooldown:  aws.Int64(60),
			TargetValue:      aws.Float64(50.0),
		},
	})
}

func GetScanStatus(print bool) bool {

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalln(Yellow("[Err]: ") + "Unable to load SDK config")
	}
	svc_sqs := sqs.NewFromConfig(cfg)

	SQSUri, err := svc_sqs.GetQueueUrl(context.TODO(), &sqs.GetQueueUrlInput{
		QueueName: aws.String(SQSQueue),
	})

	if err != nil {
		fmt.Println(Yellow("[Err]:"), "Queue is not found, exiting ...")
		os.Exit(1)
	}

	SQSAttributes, err := svc_sqs.GetQueueAttributes(context.TODO(), &sqs.GetQueueAttributesInput{
		QueueUrl: SQSUri.QueueUrl,
		AttributeNames: []sqsTypes.QueueAttributeName{
			"ApproximateNumberOfMessages",
			"ApproximateNumberOfMessagesNotVisible",
		},
	})

	messagesLeft, _ := strconv.Atoi(SQSAttributes.Attributes["ApproximateNumberOfMessages"])
	messagesInFlight, _ := strconv.Atoi(SQSAttributes.Attributes["ApproximateNumberOfMessagesNotVisible"])

	if print {
		fmt.Println(Green("[Message]:"), "Number of packages left:", messagesLeft)
		fmt.Println(Green("[Message]:"), "Number of packages in a flight:", messagesInFlight)
	}

	if messagesLeft == 0 && messagesInFlight == 0 {
		return true
	} else {
		return false
	}
}

func StopScan() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalln(Yellow("[Err]: ") + "Unable to load SDK config")
	}

	svc_sqs := sqs.NewFromConfig(cfg)

	SQSUri, _ := svc_sqs.GetQueueUrl(context.TODO(), &sqs.GetQueueUrlInput{
		QueueName: aws.String(SQSQueue),
	})

	_, err = svc_sqs.PurgeQueue(context.TODO(), &sqs.PurgeQueueInput{
		QueueUrl: SQSUri.QueueUrl,
	})
	if err != nil {
		fmt.Println(Yellow("[Err]:"), "The scan is not stopped, exiting ...")
		os.Exit(1)
	}
	fmt.Println(Green("[Message]:"), "The messages from the Queue are purged, the scan is stopped")
}

func ServicesAvailability(print bool) bool {

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalln(Yellow("[Err]: ") + "Unable to load SDK config")
	}

	// Lambda
	svc_lambda := lambda.NewFromConfig(cfg)
	_, errFunction := svc_lambda.GetFunction(context.TODO(), &lambda.GetFunctionInput{
		FunctionName: aws.String(LambdaFunction),
	})
	if errFunction != nil {
		if print {
			fmt.Println(Yellow("[Err]:"), "Lambda is not found, exiting ...")
		}
		return false
	}

	// SQS
	svc_sqs := sqs.NewFromConfig(cfg)
	_, errSQS := svc_sqs.GetQueueUrl(context.TODO(), &sqs.GetQueueUrlInput{
		QueueName: aws.String(SQSQueue),
	})
	if errSQS != nil {
		if print {
			fmt.Println(Yellow("[Err]:"), "SQS is not found, exiting ...")
		}
		return false
	}

	// DynamoDB Tables
	svc_dynamo := dynamodb.NewFromConfig(cfg)
	errDynamo1 := waitForTable(context.TODO(), svc_dynamo, TableTargets)
	errDynamo2 := waitForTable(context.TODO(), svc_dynamo, TableBeacons)
	errDynamo3 := waitForTable(context.TODO(), svc_dynamo, TableResponses)
	if errDynamo1 != nil && errDynamo2 != nil && errDynamo3 != nil {
		if print {
			fmt.Println(Yellow("[Err]:"), "DynamoDB tables are not available, exiting ...")
		}
		return false
	}

	// Event Source
	eventTriger := false
	ListEventSourceMappingsOut, err := svc_lambda.ListEventSourceMappings(context.TODO(), &lambda.ListEventSourceMappingsInput{})

	for _, EventSourceMapping := range ListEventSourceMappingsOut.EventSourceMappings {
		if strings.Contains(*EventSourceMapping.FunctionArn, LambdaFunction) {
			eventTriger = true
			break
		}
	}
	if !eventTriger {
		if print {
			fmt.Println(Yellow("[Err]:"), "EventSourceMapping is not created for a lambda function, exiting ...")
		}
		return false
	}

	return true
}

func ClearCloudEnvironment() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalln(Yellow("[Err]: ") + "Unable to load SDK config")
	}

	// Deleting tables
	svc_dynamo := dynamodb.NewFromConfig(cfg)
	svc_dynamo.DeleteTable(context.TODO(), &dynamodb.DeleteTableInput{
		TableName: aws.String(TableTargets),
	})
	svc_dynamo.DeleteTable(context.TODO(), &dynamodb.DeleteTableInput{
		TableName: aws.String(TableBeacons),
	})
	svc_dynamo.DeleteTable(context.TODO(), &dynamodb.DeleteTableInput{
		TableName: aws.String(TableResponses),
	})

	// Deleting Lambda function
	svc_lambda := lambda.NewFromConfig(cfg)
	svc_lambda.DeleteFunction(context.TODO(), &lambda.DeleteFunctionInput{
		FunctionName: aws.String(LambdaFunction),
	})

	// Deleting SQS
	svc_sqs := sqs.NewFromConfig(cfg)
	SQSUri, _ := svc_sqs.GetQueueUrl(context.TODO(), &sqs.GetQueueUrlInput{
		QueueName: aws.String(SQSQueue),
	})
	svc_sqs.DeleteQueue(context.TODO(), &sqs.DeleteQueueInput{
		QueueUrl: SQSUri.QueueUrl,
	})

	// Deleting Source map
	ListEventSourceMappingsOut, err := svc_lambda.ListEventSourceMappings(context.TODO(), &lambda.ListEventSourceMappingsInput{})
	for _, EventSourceMapping := range ListEventSourceMappingsOut.EventSourceMappings {
		if strings.Contains(*EventSourceMapping.FunctionArn, LambdaFunction) {
			svc_lambda.DeleteEventSourceMapping(context.TODO(), &lambda.DeleteEventSourceMappingInput{
				UUID: *&EventSourceMapping.UUID,
			})
			break
		}
	}

	// Deleting Role
	svc_iam := iam.NewFromConfig(cfg)
	svc_iam.DeleteRole(context.TODO(), &iam.DeleteRoleInput{
		RoleName: aws.String(IAMRoleName),
	})
}
