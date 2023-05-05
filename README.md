# WindowsWatcher
A windows based, AI enhanced, Windows Defender Upgrade

This PowerShell script is designed to monitor and detect potentially malicious events in the Windows Event Log by leveraging the Windows Defender antivirus and a custom machine learning model. The script focuses on enhancing the security of a system by identifying and taking necessary actions against malicious events. Below is a detailed description of the script's components and their functionality:

1. Importing Libraries: The script starts by importing the required libraries: the Defender module, which provides access to Windows Defender features, and the Microsoft.ML module, which provides the necessary tools for working with the machine learning model.

2. Initializing MLContext: The script initializes the MLContext, which is an object that encapsulates the environment where the machine learning model operates.

3. Machine Learning Model Setup: The script sets up a custom machine learning model with specific features and a threshold value. The model will be used to classify security events as malicious or non-malicious.

4. Windows Defender Configuration: The script ensures that real-time monitoring is enabled in Windows Defender, providing continuous protection against malware and other threats.

5. Logging and Reporting: The script sets up a log file to store information about detected security events. This log file is created in a specified location if it does not already exist.

6. Fetching Indicators of Compromise (IOCs): The script defines a function (Get-IOCList) that fetches IOCs from an external source (FireEye API) and stores them in a list. These IOCs will be used later to match against the events in the Windows Event Log.

7. Monitoring Security Events: The script continuously monitors the Security Event Log, processing a specified number of events in each iteration. It classifies the events using the machine learning model and takes necessary actions based on the classification results.

8. Processing Security Events: The script defines a function (Process-SecurityEvent) that extracts features from each security event and checks for IOC matches. It then uses the machine learning model to classify the event as malicious or non-malicious. If an event is classified as malicious, the script calls the Remediate-MaliciousEvent function to take appropriate actions. If the event is non-malicious and logging is enabled, the event details are added to the log file.

9. Feature Extraction and Classification: The script defines a function (Get-EventFeatures) to build a feature vector for the machine learning model based on the extracted features and IOC matches. This feature vector is used to classify the event.

10. Remediation of Malicious Events: The script defines a function (Remediate-MaliciousEvent) that takes appropriate actions to mitigate the risk associated with a malicious event, such as removing the malicious item and blocking related network traffic. The details of the remediation are also logged in the log file.

11. Event Trigger for New IOCs: The script sets up a FileSystemWatcher to monitor a specific folder for new or updated IOC files. When a new IOC file is detected, the script reads the contents of the file and adds the IOCs to the existing IOC list.

12. Starting the Defender Monitor: Finally, the script starts the Defender Monitor, which initiates the continuous monitoring and processing of security events.

In summary, this script enhances system security by monitoring Windows Event Logs, fetching IOCs from an external source, and using a custom machine learning model to classify events as malicious or non-malicious. It takes appropriate actions to remediate malicious events and logs relevant information for further analysis.

### Developed by

Adam Rivers & Hello Security LLC

### Contributing 

Forks, changes, projects, bug reports, etc, are encouraged! 

### License 

This script is using a basic MIT license 
