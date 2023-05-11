describePod = {}  # dictionar cu informatiile utile despre fiecare pod
change_dict = {}


def getNewPodsName(logsDictionary):  # se extrag podurile care au fost create recent
    strNames = []
    for element in logsDictionary['items']:
        if element['verb'] == 'create':
            s = element['requestURI'].split('/')
            # requestURI pentru un nou pod creat va arata similar cu: "/api/v1/namespaces/default/pods/<pod_name>/binding"
            # asa ca dau split dupa / si verific daca exista pods si binding in lista pentru a fi siguri ca s-a creat un nou pod
            if len(s) > 7 and s[5] == 'pods' and s[7] == 'binding':
                # extrag doar numele pentru pod
                strNames.append(s[6])
    return strNames


def checkImageModification(objRef, podName, formatName):
    if objRef == -1:  # tratez cazul cand objRef nu exista
        return

    # verific daca numele pod-ului a fost adaugat in dictionar
    # acest lucru se poate intamplat atunci cand script-ul de monitorizare a logs a fost pornit mai tarziu dupa ce un pod a fost creat
    # si s-a efecutat o modifiare asupra acelui pod vechi
    if describePod.get(podName, -1) == -1:
        describePod[podName] = {}

    for obj in objRef:  # parcurg fiecare container
        if obj.get('image', -1) == -1:
            continue

        refToC = {}  # referinta catre acelasi container din describePod cu obj

        refToContainers = {}  # referinta catre containers sau initContainers pentru a evita scrierea excesiva a describePod[podName]['containers/initContainers']
        if formatName == 'init':  # verific ce fel de containers caut
            if describePod[podName].get('initContainers', -1) == -1:  # verific daca 'initContainers' se afla in dictionarul pentru pod
                describePod[podName]['initContainers'] = [{'name': obj['name'], 'image': "unknown"}]  # daca nu exista, il adaug
            refToContainers = describePod[podName]['initContainers']  # iau referinta catre 'initContainers'
        else:
            if describePod[podName].get('containers', -1) == -1:  # verific daca 'containers' se afla in dictionarul pentru pod
                describePod[podName]['containers'] = [{'name': obj['name'], 'image': "unknown"}]  # daca nu exista, il adaug
            refToContainers = describePod[podName]['containers']  # iau referinta catre 'containers'

        for item in refToContainers:  # parcurg fiecare container si iau o referinta daca numele celor doua coincid
            if item['name'] == obj['name']:  # verific daca numele celor doua coincid
                refToC = item

        if podName in change_dict:
            change_dict[podName].append({'typeContainers': formatName, 'lastImage': refToC['image'], 'newImage': obj['image'], 'name': obj['name']})
        else:
            change_dict[podName] = [{'typeContainers': formatName, 'lastImage': refToC['image'], 'newImage': obj['image'], 'name': obj['name']}]

        # modific imaginea containerului
        refToC['image'] = obj['image']


def findImageName(objRef, pod, formatName):
    if objRef == -1:  # tratez cazul cand objRef nu exista
        return

    describePod[pod] = {}  # adaug numele pod-ului in dictionar
    describePod[pod][formatName] = []  # adaug tipul de containers pentru pod

    for container in objRef:  # parcurg fiecare container
        nameC = container.get('name', -1)  # extrage 'name'
        imageC = container.get('image', -1)  # extrage 'image'
        if nameC == -1 or imageC == -1:  # verific daca exista
            continue

        describePod[pod][formatName].append({'name': nameC, 'image': imageC})  # adaug informatiile extrase in dictionar


def updateForNewPods(logsDictionary):
    newPodsName = getNewPodsName(logsDictionary)  # extrag numele noilor pods

    # pentru fiecare nume de pod voi parcurge fiecare log pentru a verifica ce 'name' si 'image' are
    for pod in newPodsName:
        for log in logsDictionary['items']:
            # verific daca log-ul curent este despre un nou pod creat
            if log['verb'] == 'create' and log['objectRef'].get('resource', -1) == 'pods':
                # verific daca exista key-ul 'metadata' in dictionarul log['requestObject']
                refToMetadata = log['requestObject'].get('metadata', -1)
                if refToMetadata == -1:
                    continue

                # verific daca numele pod-ul din log este acelasi cu numele pod-ului pe care incerc sa-l caut
                generateName = refToMetadata.get('generateName', " ")
                if pod.find(generateName) == -1:
                    continue

                # verific daca exista key-ul 'spec' in dictionarul log['requestObject']
                refToSpec = log['requestObject'].get('spec', -1)
                if refToSpec == -1:
                    continue

                # extrag 'image' si 'name' pentru fiecare container din 'containers'
                refToContainers = refToSpec.get('containers', -1)
                findImageName(refToContainers, pod, "containers")

                # extrag 'image' si 'name' pentru fiecare container din 'initContainers'
                refToContainers = refToSpec.get('initContainers', -1)
                findImageName(refToContainers, pod, "initContainers")


def detectImageModification(logsDictionary):  # verificam daca unui pod i-a fost modificata imaginea
    updateForNewPods(logsDictionary)  # adaugam noile pods ce au fost create

    for log in logsDictionary['items']:  # parcurg fiecare log
        # verific daca log-ul curent este despre modificarea unui pod
        if log['verb'] == 'patch' and log['objectRef'].get('resource', -1) == 'pods':
            # verific daca exista key-ul 'spec' in dictionarul log['requestObject']
            if log['requestObject'].get('spec', -1) == -1:
                continue

            # verific daca imaginea pentru fiecare container din 'containers' s-a modificat
            refToContainers = log['requestObject']['spec'].get('containers', -1)
            checkImageModification(refToContainers, log['objectRef']['name'], "")

            # verific daca imaginea pentru fiecare container din 'initContainers' s-a modificat
            refToInitContainers = log['requestObject']['spec'].get('initContainers', -1)
            checkImageModification(refToInitContainers, log['objectRef']['name'], "init")

    return change_dict
