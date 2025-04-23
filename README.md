# Project_Prototype_HIS
Industry_Project_Prototype_HIS

This prototype HIS consists multiple modules. Each directory in this repository contains a module, which, with the except of Auth_Server, includes a script for the main functionalities (below referred to as the functionality script) of the module and a script called security.py for security configurations.

For deployment:
1. Place Front desk, LIS, RIS and Doc_workstation on 4 Windows machines. Place each of the rest of the modules on a separate Linux or Windows machine. The GUI for Windows machines are made with tkinter. The features can be seen either on the buttons or right click menus.  
2. Configure the path to the keys on the security.py script in each module. 
3. Configure the path to different databases on each module. The paths are defined at the beginning of the functionality scripts. 
4. Configure the ip addresses and ports at the beginning of each functionality script.
5. For Auth_Server, a database containing 4 id-password combinations is provided. The combinations are:
id		password
10001	bobdylon
10002	blowinginthewind
20001	johnnycash
20002	hurt
These combinations can be used for the login process.
6. If run into error f"no module named {module_name}", install the pertinent dependencies first.
7. Run Auth_Server first, then EMR, then Front desk to register for patients.
8. Once there are patients records on EMR, use Front Desk to book lab tests, radiology exams and doctor consultations.
9. Run Lab_Analyzer first. On LIS, login, display the patient table, and right click on each individual result to see and try the features. 
10. Run RIS and PACS first, then Imaging_Modality. On the modality server, when prompted to press 'S' to start an exam, press 'S'. 
11. To view medical images on RIS or on Doc_workstation, login on respective modules and the instructions are on the button and right click menus. 
12. For CDSS_AI, The model weights are not included in this repostitary because the file has exceeded github file size limit.The weight file is submitted directly on myuni. To use the model, copy the weight file to CDSS/model directory, then run ai_server.py to use the "send for AI analysis" feature on Doc_workstation. 
