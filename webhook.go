package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/op/go-logging"
	"github.com/tiaguinho/gosoap"
	"gopkg.in/matryer/try.v1"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

var logger = logging.MustGetLogger("webhook")
var format = logging.MustStringFormatter(
	`%{time:15:04:05.000} ▶ %{level} %{message}`,
)

var client *gosoap.Client

type Config struct {
	ListenerPort int    `json:"listenerPort"`
	LogLevel     string `json:"logLevel"`
	SDMWSDL      string `json:"SDMWSDL"`
	SDMUsername  string `json:"SDMUsername"`
	SDMPassword  string `json:"SDMPassword"`
}

type Problem struct {
	ProblemID          string `json:"ProblemID"`
	State              string `json:"State"`
	ProblemDetailsText string `json:"ProblemDetailsText"`
	ProblemTitle       string `json:"ProblemTitle"`
}

// LoginResponse is the response from CA SDM login operation
type LoginResponse struct {
	LoginReturn string `xml:"loginReturn""`
}

// Create RequestRequest is the request for creating an incident
type CreateRequestRequest struct {
	Sid              string `xml:"sid"`
	CreatorHandle    string `xml:"creatorHandle"`
	AttrVals         string `xml:"attrVals"`
	PropertyValues   string `xml:"propertyValues"`
	Template         string `xml:"template"`
	Attributes       string `xml:"attributes"`
	NewRequestHandle string `xml:"newRequestHandle"`
	NewRequestNumber string `xml:"newRequestNumber"`
}

// GetHandleForUserIDResponse is used for subsequent operations
type GetHandleForUserIDResponse struct {
	GetHandleForUserIDReturn string `xml:"getHandleForUseridReturn"`
}

type CreateRequestResponse struct {
	CreateRequestReturn string `xml:"createRequestReturn"`
	NewRequestHandle    string `xml:"newRequestHandle"`
	NewRequestNumber    string `xml:"newRequestNumber"`
}

func (p Problem) String() string {
	return fmt.Sprintf("ProblemID: %s, State: %s, Title: %s, Details: %s", p.ProblemID, p.State, p.ProblemTitle, p.ProblemDetailsText)
}

type Response struct {
	Error   bool   `json:"error"`
	Message string `json:"message"`
}

var config Config

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Infof("IP: %s, Method: %s, URL: %s, Content-Lenght: %d", r.RemoteAddr, r.Method, r.RequestURI, r.ContentLength)
		next.ServeHTTP(w, r)
	})
}

func SDMHandler(w http.ResponseWriter, r *http.Request) {

	resp := Response{}

	decoder := json.NewDecoder(r.Body)
	var problem Problem

	err := decoder.Decode(&problem)
	if err != nil {
		logger.Errorf("Could not parse the problem from the request body: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		resp = Response{
			Error:   true,
			Message: fmt.Sprintf("Could not parse the problem from the request body: %s", err.Error()),
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	logger.Debugf("Parsed problem: %+v", problem)

	title := fmt.Sprintf("Dynatrace - %s (Problem ID: %s, State: %s)", problem.ProblemTitle, problem.ProblemID, problem.State)
	var ticket *CreateRequestResponse
	err = try.Do(func(attempt int) (bool, error) {
		var err error
		logger.Infof("Attempting to open a ticket (%d of %d)", attempt, try.MaxRetries)
		ticket, err = openTicket(problem.ProblemDetailsText, title)
		if err != nil {
			return true, err
		}
		return false, nil
	})
	if err != nil {
		resp = Response{
			Error:   true,
			Message: fmt.Sprintf("Could not open ticket after %d tries, error: %s", try.MaxRetries, err.Error()),
		}
		w.WriteHeader(http.StatusInternalServerError)

	} else {
		logger.Infof("Opened ticket: %+s", ticket.NewRequestNumber)
		resp = Response{
			Error:   false,
			Message: fmt.Sprintf("Opened ticket: %s", ticket.NewRequestNumber),
		}
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(resp)

}

func getHandle(sid string, username string) (*GetHandleForUserIDResponse, error) {
	p := gosoap.Params{
		"sid":    sid,
		"userID": username,
	}

	err := client.Call("getHandleForUserid", p)
	if err != nil {
		return nil, err
	}

	g := GetHandleForUserIDResponse{}
	err = client.Unmarshal(&g)
	if err != nil {
		return nil, err
	}
	return &g, nil

}

func login(username string, password string) (*LoginResponse, error) {

	params := gosoap.Params{
		"username": username,
		"password": password,
	}

	err := client.Call("login", params)
	if err != nil {
		return nil, err
	}

	loginResponse := LoginResponse{}
	err = client.Unmarshal(&loginResponse)
	if err != nil {
		return nil, err
	}

	return &loginResponse, nil
}

func createRequest(sid string,
	creatorHandle string,
	attrVals []gosoap.Params,
	propertyValues []gosoap.Params,
	template string,
	attributes []gosoap.Params,
	newRequestHandle string,
	newRequestNumber string) (*CreateRequestResponse, error) {

	params := gosoap.Params{
		"sid":              sid,
		"creatorHandle":    creatorHandle,
		"attrVals":         attrVals,
		"propertyValues":   propertyValues,
		"template":         template,
		"attributes":       attributes,
		"newRequestHandle": newRequestHandle,
		"newRequestNumber": newRequestNumber,
	}

	err := client.Call("createRequest", params)
	if err != nil {
		return nil, err
	}

	r := CreateRequestResponse{}
	err = client.Unmarshal(&r)
	if err != nil {
		return nil, err
	}

	return &r, nil

}

func openTicket(description string, summary string) (*CreateRequestResponse, error) {

	l, err := login(config.SDMUsername, config.SDMPassword)
	if err != nil {
		logger.Errorf("Could not login: %s", err.Error())
		if client.Body != nil {
			logger.Debugf("The body was %s", client.Body)
		}
		return nil, err
	}
	logger.Infof("Got back token: %+v", l)

	h, err := getHandle(l.LoginReturn, "testedeconformidade")
	if err != nil {
		logger.Errorf("Could not get handle: %s", err.Error())
		if client.Body != nil {
			logger.Debugf("The body was %s", client.Body)
		}
		return nil, err
	}
	logger.Infof("Got back handle: %+v", h)

	attrs := []gosoap.Params{
		{"string": "customer"},
		{"string": h.GetHandleForUserIDReturn},

		{"string": "category"},
		{"string": "pcat:400373"},

		{"string": "description"},
		{"string": description},

		{"string": "summary"},
		{"string": summary},

		{"string": "urgency"},
		{"string": "2"},

		{"string": "impact"},
		{"string": "4"},

		{"string": "group"},
		{"string": "5FA1B7BE4CFA2E4C9B19E115AE49A642"},

		{"string": "type"},
		{"string": "crt:182"},
	}

	r, err := createRequest(l.LoginReturn,
		h.GetHandleForUserIDReturn,
		attrs,
		[]gosoap.Params{},
		"",
		[]gosoap.Params{},
		"",
		"")

	if err != nil {
		logger.Errorf("Could not create request: %s", err.Error())
		if client.Body != nil {
			logger.Debugf("The body was %s", client.Body)
		}
		return nil, err
	}

	return r, nil
}

func setUpLogging() *os.File {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)

	folderPath := filepath.Join(exPath, "../log")
	err = os.MkdirAll(folderPath, os.ModePerm)
	if err != nil {
		panic(err)
	}
	logPath := filepath.Join(folderPath, "webhook.log")
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		logger.Fatalf("Failed to open log file: %v", err)
	}

	logBackend := logging.NewLogBackend(lf, "", 0)
	logging.SetFormatter(format)
	logging.SetBackend(logBackend)

	return lf
}

func main() {

	lf := setUpLogging()
	defer lf.Close()

	logger.Infof("Reading config.json...")
	log.Printf("Reading config.json...")

	configFile, err := os.Open("config.json")
	if err != nil {
		log.Printf("Could not read config.json: %s", err.Error())
		logger.Fatalf("Could not read config.json: %s", err.Error())
	}
	defer configFile.Close()

	byteValue, _ := ioutil.ReadAll(configFile)
	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		log.Printf("Could not parse the configuration file: %s", err.Error())
		logger.Fatalf("Could not parse the configuration file: %s", err.Error())
	}

	router := mux.NewRouter()
	router.HandleFunc("/sdm", SDMHandler).Methods("POST")
	router.Use(loggingMiddleware)

	logLevel, err := logging.LogLevel(config.LogLevel)
	if err != nil {
		log.Printf("Invalid log level %s, options are CRITICAL, ERROR, WARNING, INFO, DEBUG", config.LogLevel)
		logger.Fatalf("Invalid log level %s, options are CRITICAL, ERROR, WARNING, INFO, DEBUG", config.LogLevel)

	}
	logging.SetLevel(logLevel, "webhook")
	try.MaxRetries = 50

	client, err = gosoap.SoapClient(config.SDMWSDL)
	if err != nil {
		log.Printf("Invalid log level %s, options are CRITICAL, ERROR, WARNING, INFO, DEBUG", config.LogLevel)
		logger.Fatalf("Could not create the Soap Client with WSDL: %s", err.Error())
	}

	logger.Infof("Server started at port %d\n", config.ListenerPort)
	log.Printf("Server started at port %d\n", config.ListenerPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", config.ListenerPort), router))

}
