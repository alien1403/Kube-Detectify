import json
import re

# JSON config file containing malicious commands and keywords to search for
commandPath = 'Config Files/malicious-commands-and-keywords.json'
# JSON config file containing key-value pairs of attack severity rankings
# and their numerical value in ascending order of severity
levelPath = 'Config Files/warning-levels.json'

# function receives a list of container specifications extracted from a
# K8s resource and returns a dictionary of the commands that are configured
# to be executed within the containers and their severity
def extractAndClassifyCommands(containerList):
    # the contents of both config files are loaded into python dictionaries
    warningLevels = json.loads(open(levelPath, 'r').read())
    maliciousCommandsAndKeywords = {}
    temporaryMaliciousCommandsAndKeywords = json.loads(open(commandPath, 'r').read())
    for field in temporaryMaliciousCommandsAndKeywords:
        maliciousCommandsAndKeywords.update(temporaryMaliciousCommandsAndKeywords[field])

    # dictionary which will be returned
    classifiedCommands = {}

    for container in containerList:
        # arguments of commands can be malicious if certain commands are configured to be run upon creation
        # in the container image itself, but that cannot be effectively assessed at the K8s audit log level.
        # furthermore, a command run without any arguments is unlikely to be able to cause any harm, so
        # both fields are necessary in order to make a statement about the nature of the commands.
        if 'command' in container and 'args' in container:
            # a shell is spawned upon creation for multiple command execution
            if container['command'][0].strip() == '/bin/sh' or container['command'][0].strip() == '/bin/bash':
                # args: ['-c', 'command1; command2; ...']
                # the second string within the list stored in the 'args' field contains the chaining of commands.
                # this string will be split in the places where command-chaining operators can be found and the
                # substrings will get stripped, formatted and joined into a one-liner

                # REGEX breakdown:
                # a capturing group of either ';', '&&' or '||' (command-chaining operators)
                command = ' '.join([' '.join(command.strip().split()) for command in re.split(r'(;|&{2}|\|{2})', container['args'][1])])

            # a single command is executed by the container
            else:
                # formatted command and arguments as a single line
                command = container['command'][0].strip() + ' ' + ' '.join([' '.join(arg.strip().split()) for arg in container['args']])

            # only new commands will get verified
            if command not in classifiedCommands:
                # checking all configured malicious commands and keywords as substrings of given command
                for maliciousCommandOrKeyword in maliciousCommandsAndKeywords:
                    if maliciousCommandOrKeyword in command:
                        # multiple malicious keywords were found in the same container command
                        if command in classifiedCommands:
                            # only the highest-ranked keyword will be stored as the value of the container command
                            if warningLevels[maliciousCommandsAndKeywords[maliciousCommandOrKeyword]] > \
                                    warningLevels[classifiedCommands[command]]:
                                classifiedCommands[command] = maliciousCommandsAndKeywords[
                                    maliciousCommandOrKeyword]

                        # first occurrence of a keyword in the container command
                        else:
                            classifiedCommands[command] = maliciousCommandsAndKeywords[maliciousCommandOrKeyword]

    return classifiedCommands
