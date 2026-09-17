package clusterlink

import (
	"NetManager/events"
	"NetManager/logger"
	"NetManager/utils"
	"encoding/json"
	"log"
	"sync"
	"time"

	messaging "github.com/oakestra/oakestra/libraries/oakestra_messaging_go"
)

var runningHandlers = utils.NewStringSlice()
var runningHandlersLock sync.RWMutex

// selfDestructTimeout is a variable so tests can shorten it. The doc comment on
// startSelfDestructTimeout still talks about 5 minutes, but 10 seconds is what ships.
var selfDestructTimeout = 10 * time.Second

type jobUpdatesTimer struct {
	eventManager events.EventManager
	job          string
	instance     int
	topic        string
	env          jobEnvironmentManagerActions
}

type jobEnvironmentManagerActions interface {
	RefreshServiceTable(sname string)
	RemoveServiceEntries(sname string)
	IsServiceDeployed(fullSnameAndInstance string) bool
}

type interestDeregisterRequest struct {
	Appname string `json:"appname"`
}

func (jut *jobUpdatesTimer) handle(msg messaging.Message) {
	log.Printf("Received job update regarding %s", msg.Topic)
	go jut.env.RefreshServiceTable(jut.job)
}

func (jut *jobUpdatesTimer) startSelfDestructTimeout() {
	/*
		If any worker still requires this job, reset timer. If in 5 minutes nobody needs this service, de-register the interest.
	*/
	log.Printf("self destruction timeout started for job %s", jut.job)
	eventManager := events.GetInstance()
	eventChan, _ := eventManager.Register(events.TableQuery, jut.job)
	for true {
		select {
		case <-eventChan:
			//event received, reset timer
			logger.DebugLogger().Printf("received packet event from: %s", jut.job)
			continue
		case <-time.After(selfDestructTimeout):
			if !jut.env.IsServiceDeployed(jut.job) {
				//timeout ----> job no longer required. Let's clear the interest
				log.Printf("De-registering from %s", jut.job)
				cleanInterestTowardsJob(jut.job)
				_ = getBus().Unsubscribe(jut.topic)
				runningHandlersLock.Lock()
				runningHandlers.RemoveElem(jut.job)
				runningHandlersLock.Unlock()
				eventManager.DeRegister(events.TableQuery, jut.job)
				jut.env.RemoveServiceEntries(jut.job)
				return
			}
			continue
		}
	}
}

// RegisterInterest :
/* Register an interest in a route for 5 minutes.
If the route is not used for more than 5 minutes the interest is removed
If the instance number is provided, the interest is kept until that instance is deployed in the node */
func RegisterInterest(jobName string, env jobEnvironmentManagerActions, instance ...int) {

	runningHandlersLock.Lock()
	defer runningHandlersLock.Unlock()
	if runningHandlers.Exists(jobName) {
		log.Printf("Interest for job %s already registered", jobName)
		return
	}

	instanceNumber := -1
	if len(instance) > 0 {
		instanceNumber = instance[0]
	}

	jobTimer := jobUpdatesTimer{
		eventManager: events.GetInstance(),
		job:          jobName,
		env:          env,
		instance:     instanceNumber,
	}

	jobTimer.topic = "jobs/" + jobName + "/updates_available"
	_ = getBus().Subscribe(jobTimer.topic, jobTimer.handle)
	log.Printf("Subscribed to %s ", jobTimer.topic)
	runningHandlers.Add(jobTimer.job)
	go jobTimer.startSelfDestructTimeout()
}

func IsInterestRegistered(jobName string) bool {
	runningHandlersLock.RLock()
	defer runningHandlersLock.RUnlock()
	if runningHandlers.Exists(jobName) {
		return true
	}
	return false
}

func cleanInterestTowardsJob(jobName string) {
	request := interestDeregisterRequest{Appname: jobName}
	jsonreq, _ := json.Marshal(request)
	_ = publish("interest/remove", string(jsonreq))
}
