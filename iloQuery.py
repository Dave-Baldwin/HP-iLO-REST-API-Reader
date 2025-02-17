import logging
import configparser
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from paho.mqtt import client as mqtt_client
import time
from datetime import datetime, date, timezone
import os
from sys import exit

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(filename='iLOQueryReport.log', encoding='utf-8', level=logging.INFO)

# Read configuration
config_file = os.path.join(os.path.dirname(__file__), "inputs.ini")
config = configparser.ConfigParser()
config.read(config_file)

# Get values from config.ini file
iloUsername = config["DEFAULT"]["iloUsername"]
iloPassword = config["DEFAULT"]["iloPassword"]
iLOIP = config["DEFAULT"]["iloIP"]
port = config["DEFAULT"].getint("mqttPort")  # Convert to integer if needed
broker = config["DEFAULT"]["mqttBrokerIP"]
siteName = config["DEFAULT"]["siteName"]

client_id = f'python-mqtt-iLOReporter'

ServerHealthTopic = siteName + "Liberty/Network/HPServer/HealthSummaryOK"
ServerWattsTopic = siteName + "/Network/HPServer/PowerConsumptionW"
ServerPowerSuppliesTopic = siteName + "/Network/HPServer/PowerSuppliesOK"
ServerDiskDrivesTopic = siteName + "/Network/HPServer/DiskDrivesOK"
ServerProcessorsTopic = siteName + "/Network/HPServer/ProcessorsOK"
ServerLogicalDrivesTopic = siteName + "/Network/HPServer/LogicalDrivesOK"
ServerArrayControllerTopic = siteName + "/Network/HPServer/ArrayControllerOK"
ServerStorageEnclosureTopic = siteName + "/Network/HPServer/StorageEnclosureOK"
ServerFansTopic = siteName + "/Network/HPServer/FansOK"
ServerTempsTopic = siteName + "/Network/HPServer/TempsOK"
ServerMemoryTopic = siteName + "/Network/HPServer/MemoryOK"
ServerMemoryOtherTopic = siteName + "/Network/HPServer/MemoryOtherStatus"
QuerySuccessTopic = siteName + "/Network/HPServer/iLOQueryOK"
QueryDateTimeTopic = siteName + "/Network/HPServer/LastiLOQueryDateTime"

enclOK = False
memOK = False
processorsOK = False
logDrivesOK = False
diskDrivesOK = False
controllerOK = False
tempsOK = False
fansOK = False
chassisOK = False
powerSupplOK = False


logging.info("=========== " + datetime.now().strftime("%m/%d/%Y") + " ===============")
logging.info(datetime.now().strftime("%H:%M:%S") + " || Beginning ILO query of " + iLOIP + "..")

## assume script works as expected
scriptOK = True
## this may be set false below based on any number of abnormal conditions, HTTP return values not as expected, etc.

## initialize MQTT client connection to broker
client = mqtt_client.Client(client_id)    ## updated for newer paho.mqtt version?
##client = mqtt_client.Client(client_id, callback_api_version=mqtt_client.CallbackAPIVersion.VERSION2)
##logging.info("MQTT client ID set")
##client.username_pw_set(username, password)
##client.on_connect = on_connect
##logging.info("MQTT on_connect callback function set")
try:
    logging.info("Connecting to MQTT broker...")
    client.connect(broker, port) #connect to broker
except:
    logging.info("MQTT broker connection failed")
    scriptOK = False

## don't need a MQTT loop since we are only publishing.
#client.loop_start()

## report overall iLO query status to broker
if (not scriptOK):
    logging.info("MQTT broker connection problem; skipping rest of iLO query script as we won't be able to report the data anyway.")
else:

    ## only bother doing the rest of the script if the MQTT connection was OK.

    ## GET Request
    ##response = requests.get(
    ###    "https://192.168.1.1/", 
    ##    headers=headers, 
    ##    verify=False  # <---- Added
    ##)

    ## POST Request

    headers = {'Content-type': 'application/json'}
    data = {'Password': iloPassword,'UserName': iloUsername}

    r = requests.post( 
        "https://" + iLOIP + "/redfish/v1/Sessions/", 
        headers=headers, 
        json=data,
        verify=False
    )
    
    f = open("session.json", 'w')
    f.write(r.text)
    f.close()

    if r.status_code != 201:
        scriptOK = False
        logging.info("Problem with initial login")
    else:
        ##logging.info("Initial login returned 201, OK.")

        ##if response == "<Response [201]>":
        ## response.text - not helpful, just shows Messages body from iLO

        ##logging.info("Return code: ")
        ##logging.info(r.status_code)
        ##logging.info(r.ok)
        ##logging.info(r.raise_for_status())

        ##logging.info(r.headers)

        ##logging.info(r.headers["Location"])     ## this is what we should delete against
        delLoc = r.headers["Location"]
        ##logging.info(r.headers["X-Auth-Token"])     ## this token is needed elsewhere
        authToken = r.headers["X-Auth-Token"]
        ##logging.info(authToken)

        ## new headers for all successive requests includes X-Auth-Token
        headers = {'Content-type': 'application/json','X-Auth-Token': authToken}

        ##logging.info("iLO Status information: ")
        ##logging.info("------------------------")


        #################################################
        ###### POWER SUPPLIES INFO ######################
        #################################################

        r1 = requests.get( 
            "https://" + iLOIP + "/redfish/v1/Chassis/1/Power/", 
            headers=headers, 
            verify=False
        )
        
        f = open("power.json", 'w')
        f.write(r1.text)
        f.close()

        if r1.status_code != 200:
            scriptOK = False
        else:
            
            ##logging.info("Return code: ")
            ##logging.info(r1.status_code)
            ##logging.info(r1.text)

            powerTree = json.loads(r1.text)
            ps1Status = powerTree['PowerSupplies'][0]['Status']['Health']
            ps2Status = powerTree['PowerSupplies'][1]['Status']['Health']
            ##logging.info("PS1 status: ")
            ##logging.info(ps1Status)
            ##logging.info("PS2 status: ")
            ##logging.info(ps2Status)

            if (ps1Status != "OK") or (ps2Status != "OK"):
                powerSupplOK = False
                logging.info("Power Supplies NOT OK, ")
            else:
                powerSupplOK = True

            currPowerWatts = powerTree['PowerConsumedWatts']
            #logging.info("Server Power consumption in Watts: ")
            #logging.info(currPowerWatts)

        #logging.info("Power supplies OK: ")
        #logging.info(powerSupplOK)

        #################################################
        ###### CHASSIS INFO #############################
        #################################################

        ## assume chassis OK
        chassisOK = True

        r2 = requests.get( 
            "https://" + iLOIP + "/redfish/v1/Chassis/1/", 
            headers=headers, 
            verify=False
        )
        
        f = open("chassis.json", 'w')
        f.write(r2.text)
        f.close()

        if r2.status_code != 200:
            scriptOK = False
        else:

            ##logging.info("Chassis request return code: ")
            ##logging.info(r2.status_code)
            ##logging.info(r2.text)

            chassisTree = json.loads(r2.text)
            chassisStatus = chassisTree["Status"]["Health"]
            #logging.info("Chassis status: ")
            #logging.info(chassisStatus)
            if chassisStatus != "OK":
                chassisOK = False

        #################################################
        ###### THERMAL INFO #############################
        #################################################

        r4 = requests.get( 
            "https://" + iLOIP + "/redfish/v1/Chassis/1/Thermal/", 
            headers=headers, 
            verify=False
        )
        
        f = open("thermal.json", 'w')
        f.write(r4.text)
        f.close()

        if r4.status_code != 200:
            scriptOK = False
        else:

            ##logging.info("Thermal request return code: ")
            ##logging.info(r4.status_code)
            ##logging.info(r4.text)
            thermalTree = json.loads(r4.text)

            ## begin by assuming all fans are OK
            fansOK = True

            for x in range(7):
                if "Health" in thermalTree["Fans"][x]["Status"]:
                    #logging.info("Health key exists in JSON data")
                    if thermalTree["Fans"][x]["Status"]["Health"] != "OK":
                        fansOK = False
                        logging.info("Fan " + str(x+1) + " NOT OK, ")
                    #else:
                        #logging.info("Fan " + str(x+1) + " OK, ")
                #else:
                    #logging.info("Key doesn't exist in JSON data")
                    #logging.info("Fan index ")
                    #logging.info(x)
                    #logging.info(" is absent")

            ##logging.info("")
            #logging.info("Fans OK: ")
            #logging.info(fansOK)


            ## begin by assuming all temperatures are OK
            tempsOK = True

            for x in range(41):
                if "Health" in thermalTree["Temperatures"][x]["Status"]:
                    #logging.info("Health key exists in JSON data")
                    if thermalTree["Temperatures"][x]["Status"]["Health"] != "OK":
                        tempsOK = False
                        logging.info("Temp " + str(x+1) + " NOT OK, ")
                    #else:
                        #logging.info("Temp " + str(x+1) + " OK, ")
                #else:
                    #logging.info("Health Key doesn't exist in JSON data for Temperature index ")
                    #logging.info(x)
                    #logging.info(" is absent")

            ##logging.info("")
            #logging.info("Temps OK: ")
            #logging.info(tempsOK)

        ##ps1Status = chassisTree['PowerSupplies'][0]['Status']['Health']

        #################################################
        ###### STORAGE ARRAY CONTROLLER INFO ###########
        #################################################

        r5 = requests.get( 
            "https://" + iLOIP + "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/", 
            headers=headers, 
            verify=False
        )
        
        f = open("storageArrayControllers.json", 'w')
        f.write(r5.text)
        f.close()

        if r5.status_code != 200:
            scriptOK = False
        else:

            ##logging.info("Smart Storage array controller request return code: ")
            ##logging.info(r5.status_code)
            ##logging.info(r5.text)
            controllerTree = json.loads(r5.text)

            ## begin by assuming all is OK
            controllerOK = True

            if "Health" in controllerTree["Status"]:
                #logging.info("Health key exists in JSON data")
                if controllerTree["Status"]["Health"] != "OK":
                    controllerOK = False
                    logging.info("Array Controllers NOT OK, ")
            else:
                logging.info("Key doesn't exist in JSON data")
                ## this SHOULD exist, mark OK as false
                controllerOK = False
                    
            #logging.info("Smart Storage Controller OK: ")
            #logging.info(controllerOK)


        #################################################
        ###### DISK DRIVE INFO ##########################
        #################################################

        r6 = requests.get(
            "https://" + iLOIP + "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/DiskDrives/", 
            headers=headers, 
            verify=False
        )
        
        f = open("diskDrives.json", 'w')
        f.write(r6.text)
        f.close()

        if r6.status_code != 200:
            scriptOK = False
        else:

            ##logging.info("Disk drive list request return code: ")
            ##logging.info(r6.status_code)
            ##logging.info(r6.text)
            diskDriveTree = json.loads(r6.text)

            ## begin by assuming all drives are OK
            diskDrivesOK = True

            driveCount = diskDriveTree["Members@odata.count"]
            ##logging.info(driveCount)

            ## if driveCount isn't 8, we have a problem!
            if driveCount != 8:
                diskDrivesOK = False

            ## cycle through all 'Members'
            for x in range(driveCount):     ## 8 items, so 0 -> 7 - this is how RANGE works!
                driveURL = "https://" + iLOIP + "" + diskDriveTree["Members"][x]["@odata.id"]
                ##logging.info(driveURL)
                rDiskDrive = requests.get(
                    driveURL, 
                    headers=headers,
                    verify=False
                )
                
                f = open("diskDrive" + str(x) + ".json", 'w')
                f.write(rDiskDrive.text)
                f.close()

                ##logging.info(rDiskDrive.status_code)

                indivDriveTree = json.loads(rDiskDrive.text)
                if "Health" in indivDriveTree["Status"]:
                    #logging.info("Health key exists in JSON data")
                    if indivDriveTree["Status"]["Health"] != "OK":
                        diskDrivesOK = False
                        logging.info("Disk Drive Status not OK!, ")
                    #else:
                        #logging.info("Disk drive " + str(x+1) + " OK, ")
                else:
                    logging.info("Key doesn't exist in JSON data")
                    ## this SHOULD exist, mark OK as false
                    diskDrivesOK = False

            ##logging.info("")
            #logging.info("Disk Drives OK: ")
            #logging.info(diskDrivesOK)


        #################################################
        ###### LOGICAL DRIVE INFO ##########################
        #################################################

        r7 = requests.get(
            "https://" + iLOIP + "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/LogicalDrives/", 
            headers=headers, 
            verify=False
        )

        f = open("logicalDrives.json", 'w')
        f.write(r7.text)
        f.close()

        if r7.status_code != 200:
            scriptOK = False
        else:

            ##logging.info("Logical drive list request return code: ")
            ##logging.info(r7.status_code)
            ##logging.info(r7.text)
            logDriveTree = json.loads(r7.text)

            ## begin by assuming all drives are OK
            logDrivesOK = True

            logDriveCount = logDriveTree["Members@odata.count"]
            ##logging.info(logDriveCount)

            ## if driveCount isn't 4, we have a problem!
            if logDriveCount != 4:
                logDrivesOK = False

            ## cycle through all 'Members'
            for x in range(logDriveCount):     ## 4 items, so 0 -> 3 - this is how RANGE works!
                logDriveURL = "https://" + iLOIP + "" + logDriveTree["Members"][x]["@odata.id"]
                ##logging.info(logDriveURL)
                rLogDrive = requests.get(
                    logDriveURL, 
                    headers=headers,
                    verify=False
                )
                
                f = open("logicalDrive" + str(x) + ".json", 'w')
                f.write(rLogDrive.text)
                f.close()

                ##logging.info(rLogDrive.status_code)

                indivLogDriveTree = json.loads(rLogDrive.text)
                if "Health" in indivLogDriveTree["Status"]:
                    #logging.info("Health key exists in JSON data")
                    if indivDriveTree["Status"]["Health"] != "OK":
                        logDrivesOK = False
                    #else:
                        #logging.info("Logical drive " + str(x+1) + " OK, ")
                else:
                    logging.info("Key doesn't exist in JSON data")
                    ## this SHOULD exist, mark OK as false
                    logDrivesOK = False

            ##logging.info("")
            #logging.info("Logical Drives OK: ")
            #logging.info(logDrivesOK)

        #################################################
        ###### PROCESSORS INFO ##########################
        #################################################

        r8 = requests.get(
            "https://" + iLOIP + "/redfish/v1/Systems/1/Processors/", 
            headers=headers, 
            verify=False
        )
        
        f = open("processors.json", 'w')
        f.write(r8.text)
        f.close()

        if r8.status_code != 200:
            scriptOK = False
        else:

            ##logging.info("Processors list request return code: ")
            ##logging.info(r8.status_code)
            ##logging.info(r8.text)
            processorsTree = json.loads(r8.text)

            ## begin by assuming all processors are OK
            processorsOK = True

            processorsCount = processorsTree["Members@odata.count"]
            ##logging.info(processorsCount)

            ## if processors count isn't 2, we have a problem!
            if processorsCount != 2:
                processorsOK = False

            ## cycle through all 'Members'
            for x in range(processorsCount):     ## 2 items, so 0 -> 1 - this is how RANGE works!
                processorURL = "https://" + iLOIP + "" + processorsTree["Members"][x]["@odata.id"]
                ##logging.info(processorURL)
                rProc = requests.get(
                    processorURL, 
                    headers=headers,
                    verify=False
                )
                
                f = open("processor" + str(x) + ".json", 'w')
                f.write(rProc.text)
                f.close()

                ##logging.info(rProc.status_code)

                procTree = json.loads(rProc.text)
                if "Health" in procTree["Status"]:
                    #logging.info("Health key exists in JSON data")
                    if procTree["Status"]["Health"] != "OK":
                        processorsOK = False
                    #else:
                        #logging.info("Processor " + str(x+1) + " OK, ")
                else:
                    logging.info("Key doesn't exist in JSON data")
                    ## this SHOULD exist, mark OK as false
                    processorsOK = False

            ##logging.info("")
            #logging.info("Processors OK: ")
            #logging.info(processorsOK)

        #################################################
        ###### MEMORY INFO ##############################
        #################################################

        r9 = requests.get(
            "https://" + iLOIP + "/redfish/v1/Systems/1/Memory/", 
            headers=headers, 
            verify=False
        )
        
        f = open("memory.json", 'w')
        f.write(r9.text)
        f.close()

        memOtherStatus = False

        if r9.status_code != 200:
            scriptOK = False
        else:

            ##logging.info("Memory list request return code: ")
            ##logging.info(r9.status_code)
            ##logging.info(r9.text)
            memTree = json.loads(r9.text)

            ## begin by assuming all memory is OK
            memOK = True

            memCount = memTree["Members@odata.count"]
            ##logging.info(memCount)

            ## if memory count isn't 6, we have a problem!
            if memCount != 6:
                memOK = False

            ## cycle through all 'Members'
            for x in range(memCount):     ## 6 items, so 0 -> 5 - this is how RANGE works!
                memURL = "https://" + iLOIP + "" + memTree["Members"][x]["@odata.id"]
                ##logging.info(memURL)
                rMem = requests.get(
                    memURL, 
                    headers=headers,
                    verify=False
                )
                
                f = open("memory" + str(x) + ".json", 'w')
                f.write(rMem.text)
                f.close()

                ##logging.info(rMem.status_code)

                indivMemTree = json.loads(rMem.text)
                if "DIMMStatus" in indivMemTree:
                    #logging.info("DimmStatus key exists in JSON data")
                    if indivMemTree["DIMMStatus"] != "GoodInUse":
                        #logging.info("Memory " + str(x+1) + " OK, ")
                        if indivMemTree["DIMMStatus"] == "Other":
                            memOtherStatus = True
                            logging.info("**Memory " + str(x+1) + " reports OTHER status**")
                            ## this seems acceptable, we'll tell openHAB that something is a bit off ..
                        else:
                            logging.info("")
                            logging.info("**Memory " + str(x+1) + " NOT OK***")
                            logging.info(indivMemTree["DIMMStatus"])
                            
                    ##else:
                        ##logging.info("Memory " + str(x+1) + " OK, ")
                else:
                    logging.info("Key doesn't exist in JSON data")
                    ## this SHOULD exist, mark OK as false
                    memOK = False
                    
            ##logging.info("")
            #logging.info("Memory OK: ")
            #logging.info(memOK)
            #logging.info("Memory reporting OTHER status?: ")
            #logging.info(memOtherStatus)

        #################################################
        ###### STORAGE ENCLOSURES INFO ##################
        #################################################

        r10 = requests.get(
            "https://" + iLOIP + "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/StorageEnclosures/", 
            headers=headers, 
            verify=False
        )
        
        f = open("storageEnclosures.json", 'w')
        f.write(r10.text)
        f.close()

        if r10.status_code != 200:
            scriptOK = False
        else:

            ##logging.info("Storage enclosures list request return code: ")
            ##logging.info(r10.status_code)
            ##logging.info(r10.text)
            enclsTree = json.loads(r10.text)

            ## begin by assuming all enclosures are OK
            enclOK = True

            enclCount = enclsTree["Members@odata.count"]
            #logging.info(enclCount)

            ## if enclosures count isn't 1, we have a problem!
            if enclCount != 1:
                enclOK = False

            ## cycle through all 'Members'
            for x in range(enclCount):     ## 1 items, so 0 -> 0 - this is how RANGE works!
                enlcURL = "https://" + iLOIP + enclsTree["Members"][x]["@odata.id"]
                #logging.info(enlcURL)
                rEncl = requests.get(
                    enlcURL, 
                    headers=headers,
                    verify=False
                )
                
                f = open("enclosure" + str(x) + ".json", 'w')
                f.write(rEncl.text)
                f.close()

                if rEncl.status_code != 200:
                    scriptOK = False
                    logging.info("Problem with retrieving enclosuring information")
                else:
                    
                    indivEnclTree = json.loads(rEncl.text)
                    if "Health" in indivEnclTree["Status"]:
                        #logging.info("Health key exists in JSON data")
                        if indivEnclTree["Status"]["Health"] != "OK":
                            enclOK = False
                            ##logging.info("")
                            logging.info("**Enclosure " + str(x+1) + " NOT OK***")
                        #else:
                            #logging.info("Enclosure " + str(x+1) + " OK, ")
                    else:
                        logging.info("Key doesn't exist in JSON data")
                        ## this SHOULD exist, mark OK as false
                        enclOK = False

            ##logging.info("")
            #logging.info("Storage enclosures OK: ")
            #logging.info(enclOK)

        #################################################
        ### END iLO LOGIN SESSION #######################
        #################################################

        headers = {'Content-type': 'application/json','X-Auth-Token': authToken}
        rDel = requests.delete( 
            delLoc,     ## original delete location URL given in login
            headers=headers, 
            verify=False
        )
        
        f = open("delete.json", 'w')
        f.write(rDel.text)
        f.close()

        ##logging.info("Terminate iLO API session: ")
        ##logging.info("------------------------")
        ##logging.info("Return code on Delete session: ")
        ##logging.info(rDel.status_code)

        if rDel.status_code != 200:
            scriptOK = False
            logging.info("Terminate iLO API session returned a problem status code, not 200, PROBLEM.")
        else:
            logging.info("Terminate iLO API session returned 200, OK.")

        logging.info(datetime.now().strftime("%H:%M:%S") + " || ILO queries complete.")
        

        if (enclOK and memOK and processorsOK and logDrivesOK and diskDrivesOK and controllerOK and tempsOK and fansOK and chassisOK and powerSupplOK):
            ##logging.info("
            logging.info("****************")
            logging.info("Overall server health appears OK.")
            logging.info("****************")
            ## publish value to broker
            resultRpt = client.publish(ServerHealthTopic, True)
            
        else:
            logging.info("****************")
            logging.info("Overall server health appears DEGRADED.")
            logging.info("****************")
            ## publish value to broker
            resultRpt = client.publish(ServerHealthTopic, False)

        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: iLO Health Summary")
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Health Summary via MQTT")
        time.sleep(0.1)

        ## publish other values to broker
        resultRpt = client.publish(ServerWattsTopic, currPowerWatts)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: iLO Power Consumption: " + str(currPowerWatts))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Health Summary via MQTT")
        time.sleep(0.1)

        resultRpt = client.publish(ServerPowerSuppliesTopic, powerSupplOK)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: iLO Power Supplies Status: " + str(powerSupplOK))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Power Supplies Status via MQTT")
        time.sleep(0.1)

        resultRpt = client.publish(ServerDiskDrivesTopic, diskDrivesOK)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: iLO Disk Drives Status: " + str(diskDrivesOK))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Disk Drives Status via MQTT")
        time.sleep(0.1)

        resultRpt = client.publish(ServerProcessorsTopic, processorsOK)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: iLO Processors Status: " + str(processorsOK))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Processors Status via MQTT")
        time.sleep(0.1)

        resultRpt = client.publish(ServerLogicalDrivesTopic, logDrivesOK)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: iLO Logical Drives Status:" + str(logDrivesOK))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Logical Drives Status via MQTT")
        time.sleep(0.1)

        resultRpt = client.publish(ServerArrayControllerTopic, controllerOK)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: iLO Array Controller Status:" + str(controllerOK))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Array Controller Status via MQTT")
        time.sleep(0.1)

        resultRpt = client.publish(ServerStorageEnclosureTopic, enclOK)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: iLO Array Controller Status: " + str(enclOK))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Array Controller Status via MQTT")
        time.sleep(0.1)
       
        resultRpt = client.publish(ServerFansTopic, fansOK)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: Fans Status: " + str(fansOK))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Fans Status via MQTT")
        time.sleep(0.1)

        resultRpt = client.publish(ServerTempsTopic, tempsOK)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: Temperatures Status: " + str(tempsOK))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Temperatures Status via MQTT")
        time.sleep(0.1)
        
        resultRpt = client.publish(ServerMemoryTopic, memOK)
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: Memory Status: " + str(memOK))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Memory Status via MQTT")
        time.sleep(0.1)

        resultRpt = client.publish(ServerMemoryOtherTopic, memOtherStatus) 
        if resultRpt[0] == 0:
           logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: Memory OTHER Status: " + str(memOtherStatus))
        else:
            logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Memory OTHER report Status via MQTT")
        time.sleep(0.1)



    ## last overall status report via MQTT
    ## report overall iLO query status to broker
    resultRpt = client.publish(QuerySuccessTopic, scriptOK)
    if resultRpt[0] == 0:
       logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: Overall iLO Query Success/Status")
    else:
        logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Query Success/Status")
    time.sleep(0.1)

    ## report date-time of last query/report via MQTT
    resultRpt = client.publish(QueryDateTimeTopic, datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
    if resultRpt[0] == 0:
       logging.info(datetime.now().strftime("%H:%M:%S") + " || MQTT Report OK: iLO Query DateTime stamp")
    else:
        logging.info(datetime.now().strftime("%H:%M:%S") + " || PROBLEM reporting iLO Query DateTime stamp")
    time.sleep(0.1)    
    
    ## disconnect from MQTT broker
    client.disconnect()
    logging.info(datetime.now().strftime("%H:%M:%S") + " || Disconnected from MQTT broker.")

if (scriptOK):
    logging.info("Script executed OK, no issues encountered.")
else:
    logging.info("iLO query script encountered PROBLEMS!")
exit()
