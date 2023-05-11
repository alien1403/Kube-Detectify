from flask import Flask, request, render_template, send_file
import json
import ContainerAdministrationCommandAbuse
import ContainerDeployment
import InternalImageImplanting


app = Flask(__name__)


# for archiving, all the different types of attack warnings will be stored in JSON files on the disk.
# while warnings resulted from the detection of attacks in the current flask session will be stored
# in temporary dictionaries at first and showed in the UI in a human-friendly format, these new warnings
# will be appended to their corresponding JSON file immediately after detection.
commandAbuseWarningPath = 'Log Storage/command-abuse-warnings.json'
# a copy of the JSON file is converted to a python dictionary to be rewritten to the original file later
try:
    commandAbuseWarningGlobal = json.loads(open(commandAbuseWarningPath, 'r').read())
except:
    commandAbuseWarningGlobal = {}
# a temporary session dictionary is created
commandAbuseWarningsForCurrentSession = {}


# same process occurs here as the one explained above
containerDeploymentWarningPath = 'Log Storage/container-deployment-warnings.json'
try:
    containerDeploymentWarningGlobal = json.loads(open(containerDeploymentWarningPath, 'r').read())
except:
    containerDeploymentWarningGlobal = {}
containerDeploymentWarningsForCurrentSession = {}


# same process occurs here as the one explained above
imageImplantingWarningPath = 'Log Storage/image-implanting-warnings.json'
try:
    imageImplantingWarningGlobal = json.loads(open(imageImplantingWarningPath, 'r').read())
except:
    imageImplantingWarningGlobal = {}
imageImplantingWarningsForCurrentSession = {}



# route used by K8s audit log webhook
@app.route('/postLogs', methods=['POST'])
def receiveAndAnalyseAuditLogs():
    global commandAbuseWarningsForCurrentSession, containerDeploymentWarningsForCurrentSession, imageImplantingWarningsForCurrentSession

    # received JSON file is converted to a python dictionary upon being received, which is stored in its corresponding variable
    receivedLogs = request.get_json(force=True)
    print('\n\n', json.dumps(receivedLogs, indent=4), '\n\n')

    # the function used for analysing and detecting each type of attack will be called using the logs which have just been received.
    # each function returns a dictionary, which will be 'appended' to the temporary session dictionary
    commandAbuseWarningsForCurrentSession.update(ContainerAdministrationCommandAbuse.getPodsExec(receivedLogs))
    # and to the copy of the JSON file which was converted to a dictionary when the current flask session began.
    commandAbuseWarningGlobal.update(commandAbuseWarningsForCurrentSession)
    # lastly, this new 'global' dictionary (the copy) will be dumped to the original JSON file, overwriting it
    commandAbuseWarningFile = open(commandAbuseWarningPath, 'w')
    commandAbuseWarningFile.write(json.dumps(commandAbuseWarningGlobal, indent=4))
    commandAbuseWarningFile.close()

    # same process occurs here as the one explained above
    containerDeploymentWarningsForCurrentSession.update(ContainerDeployment.getMaliciousResources(receivedLogs))
    containerDeploymentWarningGlobal.update(containerDeploymentWarningsForCurrentSession)
    containerDeploymentWarningFile = open(containerDeploymentWarningPath, 'w')
    containerDeploymentWarningFile.write(json.dumps(containerDeploymentWarningGlobal, indent=4))
    containerDeploymentWarningFile.close()

    # same process occurs here as the one explained above
    imageImplantingWarningsForCurrentSession.update(InternalImageImplanting.detectImageModification(receivedLogs))
    imageImplantingWarningGlobal.update(imageImplantingWarningsForCurrentSession)
    imageImplantingWarningFile = open(imageImplantingWarningPath, 'w')
    imageImplantingWarningFile.write(json.dumps(imageImplantingWarningGlobal, indent=4))
    imageImplantingWarningFile.close()

    return "Audit logs received and analysed successfully!"


@app.route('/')
def getHomePage():
    return render_template('index.html')


@app.route('/console')
def getConsole():
    global commandAbuseWarningsForCurrentSession, containerDeploymentWarningsForCurrentSession, imageImplantingWarningsForCurrentSession

    # 3 possible arguments have been defined for the console page, corresponding to each attack type.
    # the same front-end will be used to display all 3 types of warnings, but the information
    # which will be injected will differ based on said arguments.
    scanningType = request.args['scanningType']
    warnings = {}

    if scanningType == 'command-abuse':
        warnings = commandAbuseWarningsForCurrentSession
    elif scanningType == 'container-deployment':
        warnings = containerDeploymentWarningsForCurrentSession
    elif scanningType == 'image-implanting':
        warnings = imageImplantingWarningsForCurrentSession

    return render_template('Pages/console.html', scanningType=scanningType, warnings=warnings, warnings_len=len(warnings))

    return '404 - Not Found'


@app.route('/download')
def getArchive():
    global scanningTypes, commandAbuseWarningPath, containerDeploymentWarningPath, imageImplantingWarningPath

    scanningType = request.args['scanningType']
    pathOfFileToBeDownloaded = ''

    if scanningType == 'command-abuse':
        pathOfFileToBeDownloaded = commandAbuseWarningPath
    elif scanningType == 'container-deployment':
        pathOfFileToBeDownloaded = containerDeploymentWarningPath
    elif scanningType == 'image-implanting':
        pathOfFileToBeDownloaded = imageImplantingWarningPath

    if pathOfFileToBeDownloaded:
        return send_file(pathOfFileToBeDownloaded, as_attachment=True, mimetype='txt/csv')

    return '404 - Not found'
