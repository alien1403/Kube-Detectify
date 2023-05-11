from ContainerCommandExtractAndClassify import extractAndClassifyCommands

# list of parent resources which can create a container
parentResources = ["replication-controller", "cronjob-controller",
                   "replicaset-controller", "daemon-set-controller",
                   "job-controller", "replication-controller",
                   "statefulset-controller", "deployment-controller"]

recordedResources = {}

# function which returns a dictionary of resources, based on
# a JSON string object converted to a regular dictionary
def getMaliciousResources(logs):
    global recordedResources
    maliciousResources = {}

    # 'items' field contains the audit events
    for event in logs['items']:
        # only 'creation' requests will be processed
        if event['verb'] == 'create':
            # the requestURI is split, in order to determine the nature of the resource.
            # all pods must pass the binding process, regardless of whether they were 
            # independently created or whether they are managed by parent resource.
            # pod bindings have the following URI structure: '.../pods/<pod_name>/binding'
            requestURI = event['requestURI'].split('/')

            # checking if the request is a pod binding operation
            if len(requestURI) > 7 and requestURI[5] == 'pods' and requestURI[7] == 'binding':
                # if a pod's name doesn't contain '-', the pod was created directly
                if '-' not in requestURI[6] and requestURI[6] not in recordedResources:
                    recordedResources[requestURI[6]] = ""
                    maliciousCommands = {}

                    # the binding request of pods created independently contain the specification of the container(s)
                    # itself(themselves) in one or both of the following field structures:
                    # ['requestObject']['spec']['containers']  or  ['requestObject']['spec']['initContainers']
                    if 'spec' in event['requestObject']:
                        if 'containers' in event['requestObject']['spec']:
                            maliciousCommands.update(extractAndClassifyCommands(event['requestObject']['spec']['containers']))

                        if 'initContainers' in event['requestObject']['spec']:
                            maliciousCommands.update(extractAndClassifyCommands(event['requestObject']['spec']['initContainers']))

                    # malicious commands were found inside the specification of the container(s)
                    if maliciousCommands:
                        maliciousResources[requestURI[6]] = {'type': 'pod', 'commands': maliciousCommands, 'timestamp': event['stageTimestamp']}

                else:
                    # all pods' names are appended a random hash after their parent resource,
                    # so a copy of the name of the pod without the final '-' and hash will be
                    # stored for further checking
                    supposedParentResourceName = requestURI[6].rsplit("-", 1)[0]

                    # said name copy exists in the key-store of recorded resources, so this pod belongs to it
                    if supposedParentResourceName in recordedResources and requestURI[6] not in recordedResources[supposedParentResourceName]:
                        recordedResources[supposedParentResourceName].append(requestURI[6])

                    # pod was created independently, so we check if it has been detected before, not to overwrite it
                    elif requestURI[6] not in recordedResources:
                        recordedResources[requestURI[6]] = ""
                        maliciousCommands = {}

                        # the binding request of pods created independently contain the specification of the container(s)
                        # itself(themselves) in one or both of the following field structures:
                        # ['requestObject']['spec']['containers']  or  ['requestObject']['spec']['initContainers']
                        if 'spec' in event['requestObject']:
                            if 'containers' in event['requestObject']['spec']:
                                maliciousCommands.update(extractAndClassifyCommands(event['requestObject']['spec']['containers']))

                            if 'initContainers' in event['requestObject']['spec']:
                                maliciousCommands.update(extractAndClassifyCommands(event['requestObject']['spec']['initContainers']))

                        # malicious commands were found inside the specification of the container(s)
                        if maliciousCommands:
                            maliciousResources[requestURI[6]] = {'type': 'pod', 'commands': maliciousCommands, 'timestamp': event['stageTimestamp']}


            # request wasn't a pod binding operation, so it might involve a parent resource.
            # as we are interested in finding these resources' types, it is easiest to only
            # check their creation through system components 
            elif ":" in event["user"]["username"]:
                # extracting resource type
                parentResourceType = event["user"]["username"].rsplit(":", 1)[1]

                # verifying if the resource can and does create pods
                if parentResourceType in parentResources and event["requestObject"]["kind"] == "Pod":
                    parentResourceName = event["requestObject"]["metadata"]["ownerReferences"][0]["name"]

                    # sometimes, in the audit logs, multiple events are recorded for
                    # the same resource, so we check if this resource was already recorded
                    if parentResourceName not in recordedResources:
                        recordedResources[parentResourceName] = []
                        parentResourceContainers = checkForContainerSpecification(event)

                        # parent resource creates at least one container and contains their specification
                        if parentResourceContainers:
                            maliciousCommands = extractAndClassifyCommands(parentResourceContainers)

                            # malicious commands were found inside the specification of the container(s)
                            if maliciousCommands:
                                maliciousResources[parentResourceName] = {'type': parentResourceType, 'commands': maliciousCommands, 'timestamp': event['stageTimestamp']}

    # parent resources will also store the list of pods which were
    # created through it in the dictionary they hold as a value
    for resource in maliciousResources:
        if recordedResources[resource]:
            maliciousResources[resource]['pods'] = recordedResources[resource]

    return maliciousResources



# for a given parent resource, their container specification is returned as a list, if it exists
def checkForContainerSpecification(log):
    # for all parent resources, the JSON object structure must be one of the following:
    # ['spec']['containers'/'initContainers'] or ['spec']['template']['spec']['containers'/'initContainers']
    containers = []

    if 'spec' in log['requestObject']:
        if 'containers' in log['requestObject']['spec']:
            containers.extend(log['requestObject']['spec']['containers'])

        if 'initContainers' in log['requestObject']['spec']:
            containers.extend(log['requestObject']['spec']['initContainers'])

        if 'template' in log['requestObject']['spec'] \
                and 'template' in log['requestObject']['spec']['template'] \
                and 'containers' in log['requestObject']['spec']['template']['spec']:

            if 'containers' in log['requestObject']['spec']['template']['spec']:
                containers.extend(log['requestObject']['spec']['template']['spec']['containers'])

            if 'initContainers' in log['requestObject']['spec']['template']['spec']:
                containers.extend(log['requestObject']['spec']['template']['spec']['initContainers'])


    return containers
