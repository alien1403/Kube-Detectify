from urllib.parse import unquote
from json import dumps
from datetime import datetime
import re
import json
import math

commandFrequency = {}
maliciousDictionary = {}
logsDictionary = {}
warningsDictionary = {}
warningsPrivEscDictionary = {}
ip_username = {}


def getDangerousCommands():
    global maliciousDictionary

    g = open("Config Files/malicious-commands-and-keywords.json", "r")  # fisierul de unde se citesc comenzile considerate malicioase
    JSONString = ""
    for line in g.readlines():  # citeste comenzile considerate malicioase din fisier
        JSONString += line
    maliciousDictionary = json.loads(JSONString)  # transform string-ul citit intr-un dictionar


def printCommandFrequencyByIPInFile(filename='commandsExecuted.txt'):
    fout = open(filename, "w")
    fout.write(dumps(warningsDictionary, indent=4))
    fout.close()


def getNumberOfTimesCommandWasExecutedByIP(username, ip, command):  # extrage de cate ori a fost executata o anumita comanda de catre un IP pe un user
    if commandFrequency[username].get(ip, -1) == -1 or commandFrequency[username][ip]['commands'].get(command, -1) == -1:
        return 0

    return len(commandFrequency[username][ip]['commands'][command])


def getNumberOfTimesCommandWasExecutedByUsername(username, command):  # extrage de cate ori a fost executa o anumita comanda de catre un user
    if commandFrequency.get(username, -1) == -1:
        return 0

    numberOfTimes = 0
    for ip in commandFrequency[username]:
        numberOfTimes += getNumberOfTimesCommandWasExecutedByIP(username, ip, command)

    return numberOfTimes


def getTotalNumbersOfCommandsExecutedByIP(username, ip):  # extrage numarul total de comenzi executate de un IP pe un user
    if commandFrequency[username].get(ip, -1) == -1:
        return 0

    return commandFrequency[username][ip]['totalNumberOfCommands']


def getTotalNumbersOfCommandsExecutedByUsername(username):  # extrage numarul total de comenzi executate de catre un user
    if commandFrequency.get(username, -1) == -1:
        return 0

    totalNumber = 0
    for ip in commandFrequency[username]:
        totalNumber += getTotalNumbersOfCommandsExecutedByIP(username, ip)

    return totalNumber


def increaseCommandFrequencyByIP(username, ip, commandName, commandArgs):  # incrementeaza frecventa comenzii executate de un IP pe un user
    if commandFrequency[username][ip]['commands'].get(commandName, -1) == -1:  # verific daca comanda executa exista in dictionarul pentru ip
        commandFrequency[username][ip]['commands'][commandName] = []

    commandFrequency[username][ip]['commands'][commandName].append(commandArgs)  # adaug argumentele executate la comanda
    commandFrequency[username][ip]['totalNumberOfCommands'] += 1


def eliminateExtraSpacesFromCommand(command):  # formateaza command astfel incat sa elimine spatiile consecutive si sa le inlocuiasca cu un singur spatiu
    newCommand = ""
    for word in command.split(' '):
        if len(word) == 0:
            continue
        newCommand += word + ' '

    return newCommand[:-1]


def convertStringToDate(stringDate):  # transformat un string intr-o data dupa un format predefinit
    return datetime.strptime(stringDate, '%Y-%m-%d %H:%M:%S')


def getValidStringDateFormat(stringDate):  # transforma data care apare in logs intr-un string cu un format predefinit
    # cum data din logs este de forma '2022-09-26T16:56:27.118192Z' o vom tranforma intr-un string de forma '2022-09-26 16:56:27'
    stringDate = stringDate.split('T')
    stringDate[1] = stringDate[1].split('.')[0]

    return stringDate[0] + ' ' + stringDate[1]


def getValueOfGradient(x, maxValue, baseLog=2):
    # scopul functiei este de a normaliza o valoare 'x' dupa o functie logaritmica la o valoare cuprinsa intre [1, 5]
    # daca x = 0 atunci valoarea returnata va fi 5, adica maxim, iar daca x >= maxValue atunci valoarea returnata va fi 1
    # am utilizat o functie logaritmica pentru scoate in evidenta faptul ca atunci cand o valoare creste liniar, valoare returnata va tinde usor spre 5, si nu liniar
    if x >= maxValue:
        return 1

    divisionLogValue = math.log(maxValue + 1, baseLog) / 4
    y = 5 - (math.log(x + 1, baseLog)) / divisionLogValue

    return y


def getMultiplierByCommand(totalNumberOfCommands, countCommand, countCommandUsername):
    # scopul functiei este sa returneze o valoare de multiplicitate pentru nivelul de panica
    # pentru asta vom utiliza functia logaritmica de normalizare getValueOfGradient(...)
    # se observa faptul ca daca unul dintre parametrii au o valoare foarte mica, valoarea de multiplicitate va lua o valoarea mare
    # astfel putem spune ca valoare de multiplicitate este invers proportionala fata de parametrii sau direct proportionala cu produsul normalizarii celor 3 valori 

    # normalizam variabila totalNumberOfCommands pana la maxim 63
    multiplierTNoC = getValueOfGradient(totalNumberOfCommands, 63)
    # normalizam variabila countCommand pana la maxim 7
    multiplierCC = getValueOfGradient(countCommand, 7)
    # normalizam variabila countCommandUsername pana la maxim 15
    multiplierCCU = getValueOfGradient(countCommandUsername, 15)
    # normalizam produsul celor 3 normalizari apoi scazand 1 (pentru a se obtine minim 0 sau maxim 124) de mai sus pana la maxim 40
    multiplierValue = 6 - getValueOfGradient(multiplierTNoC * multiplierCC * multiplierCCU - 1, 40)

    return multiplierValue


def getMultiplierByDates(diferenceInMinutes):
    # normalizam variabila countCommandUsername pana la maxim 2880
    multiplierValue = getValueOfGradient(diferenceInMinutes, 2880)

    return multiplierValue


def getPanicLevel(firstContactDate, currentContactDate, totalNumberOfCommands, countCommand, countCommandUsername, levelsOfRisk):
    # obtinem valoarea de multiplicitate pentru diferente de minute dintre cele doua date
    multiplierByDate = getMultiplierByDates((currentContactDate - firstContactDate).total_seconds() / 60)
    # obtinem valoarea de multiplicitate pentru comenzi
    multiplierByCommand = getMultiplierByCommand(totalNumberOfCommands, countCommand, countCommandUsername)
    # obtinem valoarea de multiplicitate pentru nivelul de risc
    multiplierByRisk = levelsOfRisk
    # multiplierValue va avea valori intre [0, 75] si se obtine prin inmultirea celor 3 valori de multiplicitate
    multiplierValue = multiplierByDate * multiplierByCommand * multiplierByRisk

    # calculam nivelul de panica prin normalizare si efectuarea unor operatii astfel incat nivelul de panica sa fie intre [0, 100]
    panicLevel = 25 * (5 - getValueOfGradient(multiplierValue, 75))

    return panicLevel


def detectPrivEsc(username, ip):  # verifica daca un user a fost accesat de un ip care nu s-a mai conectat niciodata la el
    if ip in ip_username:  # verific daca ip-ul curent exista in dictionarul cu ip-uri cunoscute
        if username in ip_username[ip]:  # verific daca username-ul curent a fost accesat de 'ip' in trecut
            return
        else:
            ip_username[ip].append(username)  # daca nu, la ip-ul curent adaug username-ul curent
    else:
        ip_username[ip] = [username]  # daca ip-ul nu exista in dictionar, il adaug si adaug username-ul curent la el

    if len(ip_username[ip]) == 2:  # daca ip-ul curent a accesat 2 username diferiti pentru prima data, atunci este posibil sa fie privilege escaladation
        warningsPrivEscDictionary[ip] = {'panicLevel' : 70}
        print(f"WARNING! IP \"{ip}\" has connected to another user for the first time!")

def getWarningsPrivEscDictionary():
    return warningsPrivEscDictionary

def alertMessages(panicLevel, username, ip, command, podName, currentDate):  # afiseaza mesaje de alerte in functi de nivelul de panica
    if panicLevel >= 45:
        if warningsDictionary.get(podName, -1) == -1:
            warningsDictionary[podName] = []
        warningsDictionary[podName].append({'username': username, 'ip': ip, 'command': command, 'panicLevel': panicLevel, 'date': str(currentDate)})

    if panicLevel < 45:
        return
    elif panicLevel < 65:
        print(f"WARNING! The user \"{username}\" with IP \"{ip}\" executed \"{command}\" within \"{podName}\"!")
    elif panicLevel < 85:
        print(f"ALERT!! The user \"{username}\" with IP \"{ip}\" executed \"{command}\" within \"{podName}\", could be an attack and should be investigated!")
    elif panicLevel < 95:
        print(f"PANIC!!! The user \"{username}\" with IP \"{ip}\" executed \"{command}\" within \"{podName}\", it is most likely an attack and should be investigated right now!")
    else:
        print(f"ATTACK!!!! The user \"{username}\" with IP \"{ip}\" tries to attack the organization using \"{command}\" within \"{podName}\", should be investigated right now!")


# extrage comenzile executate cu kubectl exec
def getPodsExec(logsDictionary):
    # se parcurge fiecare eveniment
    for log in logsDictionary['items']:
        if log['objectRef'].get('subresource', 0) == 'exec':
            # se extrage comanda din requestURI
            s = log['requestURI'].split('/')[7]
            x = re.findall(r'command=[^&]+\&', s)
            command = ""
            # se reconstruieste comanda executata
            for element in x:
                if len(command) > 0:
                    command += ' '
                element = element.replace('+', ' ')
                command += unquote(element)[8:-1]

            # elimin spatiile consecutive
            command = eliminateExtraSpacesFromCommand(command).split(' ', 1)
            if len(command) == 1:  # tratez cazul in care comanda este formata doar dintr-un singur cuvant
                command.append("")

            ip = log['sourceIPs'][0]  # iau ip-ul curent
            username = log['user']['username']  # iau username-ul curent

            if commandFrequency.get(username, -1) == -1:  # verific daca 'username' nu exista in dictionar
                commandFrequency[username] = {}  # adaug un nou dictionar pentru el, daca nu exista

            if commandFrequency[username].get(ip, -1) == -1:  # verific daca 'ip' nu exista in dictionar pentru 'username'
                commandFrequency[username][ip] = {"commands": {}, "firstContactDate": "", "totalNumberOfCommands": 0}  # adaug un nou dinctionar pentru el, daca nu exista
                commandFrequency[username][ip]["firstContactDate"] = getValidStringDateFormat(log['requestReceivedTimestamp'])  # adaug data la care a fost executata prima comanda de catre ip

            # extrag data la care a executat pentru prima data o comanda
            firstContactDate = convertStringToDate(commandFrequency[username][ip]["firstContactDate"])
            # extrag data la care a fost executata comanda curenta
            currentContactDate = convertStringToDate(getValidStringDateFormat(log['requestReceivedTimestamp']))
            # extrag numarul de comenzi totale executate de username
            totalNumberOfCommands = getTotalNumbersOfCommandsExecutedByUsername(username)
            # extrag numarul de cate ori a mai executat comanda 'command[0]' in trecut ip-ul curent
            countCommand = getNumberOfTimesCommandWasExecutedByIP(username, ip, command[0])
            # extrag numarul de cate ori a mai executat comanda 'command[0]' in trecut username-ul curent
            countCommandUsername = getNumberOfTimesCommandWasExecutedByUsername(username, command[0])
            # extrag nivelul de risc al comenzii executate
            levelsOfRisk = getRiskOfCommand(command[0] + ' ' + command[1])

            # calculez nivelul de panica
            panicLevel = getPanicLevel(firstContactDate, currentContactDate, totalNumberOfCommands, countCommand, countCommandUsername, levelsOfRisk)
            # afisez alerte in functie de nivelul de panica
            alertMessages(panicLevel, username, ip, command[0] + ' ' + command[1], log['objectRef'].get('name', 'unknown'), currentContactDate)

            # verific pentru privilege escaladation
            detectPrivEsc(username, ip)
            # incrementez frecventa comenzii
            increaseCommandFrequencyByIP(username, ip, command[0], command[1])

    return warningsDictionary


def getRiskOfCommand(command):  # returneaza nivelul de risc al comenzii executate
    levelsOfRisk = {'low': 1, 'medium': 2, 'high': 3, 'unknown': 4}  # asociez fiecare nivel de risc o anumita valoare de tip intreg
    currentRisk = 0  # variabila ce ne va ajuta sa tinem nivelul maxim de risc pe care-l prezinta o comanda

    for mal in maliciousDictionary['commands'].items():  # parcurg fiecare comanda considerata malitioasa
        maliciousCommand = mal[0]  # extrag comanda
        isTheSame = True  # variabila ce se ajuta sa vedem daca comanda executata este aceeasi cu comanda considerata malitioasa
        for word in maliciousCommand.split(' '):  # pentru fiecare cuvant din 'maliciousCommand' verific daca acesta se regaseste si in 'command'
            isTheSame &= (word in command.split(' '))

        # verific daca cele doua comenzi sunt asemanatoare si verific daca nivelul de risc al comenzii executate este mai mare decat nivelul de risc gasit pana acum
        if isTheSame == True and levelsOfRisk[mal[1]] > currentRisk:
            # iau nivelul mai mare de risc
            currentRisk = levelsOfRisk[mal[1]]

    for keyword in maliciousDictionary['keywords'].items():  # verific daca anumite cuvinte cheie exista in comanda executata
        maliciousKeyword = keyword[0]
        # verific daca exista si iau nivelul mai mare de risc
        if command.find(maliciousKeyword) != -1 and levelsOfRisk[keyword[1]] > currentRisk:
            currentRisk = levelsOfRisk[keyword[1]]

    return currentRisk


getDangerousCommands()

