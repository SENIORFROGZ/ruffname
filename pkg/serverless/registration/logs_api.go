package registration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	headerContentType  string = "Content-Type"
	routeSubscribeLogs string = "/2020-08-15/logs"
)

//requestTimeout     time.Duration = 5 * time.Second

// SubscribeLogs subscribes to the logs collection on the platform.
// We send a request to AWS to subscribe for logs, indicating on which port we
// are opening an HTTP server, to receive logs from AWS.
// When we are receiving logs on this HTTP server, we're pushing them in a channel
// tailed by the Logs Agent pipeline, these logs then go through the regular
// Logs Agent pipeline to finally be sent on the intake when we receive a FLUSH
// call from the Lambda function / client.
// logsType contains the type of logs for which we are subscribing, possible
// value: platform, extension and function.
func SubscribeLogs(id ID, url string, timeout time.Duration, payload json.Marshaler) error {

	jsonBytes, err := payload.MarshalJSON()
	if err != nil {
		return fmt.Errorf("SubscribeLogs: can't marshal subscribe JSON %v", err)
	}

	request, err := buildLogRegistrationRequest(url, HeaderExtID, headerContentType, id, jsonBytes)
	if err != nil {
		return fmt.Errorf("SubscribeLogs: can't create the PUT request: %v", err)
	}

	response, err := sendLogRegistrationRequest(&http.Client{
		Transport: &http.Transport{IdleConnTimeout: timeout},
		Timeout:   timeout,
	}, request)
	if err != nil {
		return fmt.Errorf("SubscribeLogs: while PUT subscribe request: %s", err)
	}

	if !isValidHttpCode(response.StatusCode) {
		return fmt.Errorf("SubscribeLogs: received an HTTP %s", response.Status)
	}

	return nil
}

func BuildLogRegistrationPayload(uri string, logsType string, timeoutMs int, maxBytes int, maxItems int) *LogSubscriptionPayload {
	logsTypeArray := getLogTypesToSubscribe(logsType)
	destination := &Destination{
		URI:      uri,
		Protocol: "HTTP",
	}
	buffering := &Buffering{
		TimeoutMs: timeoutMs,
		MaxBytes:  maxBytes,
		MaxItems:  maxItems,
	}
	payload := &LogSubscriptionPayload{
		Destination: *destination,
		Types:       logsTypeArray,
		Buffering:   *buffering,
	}
	return payload
}

func buildLogRegistrationRequest(url string, headerExtID string, headerContentType string, id ID, payload []byte) (*http.Request, error) {
	request, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set(headerExtID, id.String())
	request.Header.Set(headerContentType, "application/json")
	return request, nil
}

func sendLogRegistrationRequest(httpClient HttpClient, request *http.Request) (*http.Response, error) {
	return httpClient.Do(request)
}

func isValidHttpCode(statusCode int) bool {
	return statusCode < 300
}

func getLogTypesToSubscribe(envLogsType string) []string {
	var logsType []string
	if len(envLogsType) > 0 {
		var logsType []string
		parts := strings.Split(strings.TrimSpace(envLogsType), " ")
		for _, part := range parts {
			part = strings.ToLower(strings.TrimSpace(part))
			switch part {
			case "function", "platform", "extension":
				logsType = append(logsType, part)
			default:
				log.Warn("While subscribing to logs, unknown log type", part)
			}
		}
	} else {
		logsType = []string{"platform", "function", "extension"}
	}
	return logsType
}
