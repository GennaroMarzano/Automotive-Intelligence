def text_to_read():
    text = '''                                                                                                                                                                    Introduction

Welcome to our CVE analysis tool from the National Vulnerability Database (NVD). This tool acquires and analyzes the CVEs of interest to you from the NVD database, allowing you to focus
about vulnerabilities relevant to your work or objective.
To use this tool, you need to follow some preliminary steps. Below you will find detailed instructions on how to obtain and configure an API key from the NVD site, which you will need to enter as an environment variable
in your operating system.


Procedure for obtaining an API key from the NVD site

 1 - Visit the NVD (National Vulnerability Database) website: Access the official website of the National Vulnerability Database at https://nvd.nist.gov/.

 2 - Registration or login: If you don't have an account, create a new account. If you already have an account, log in using your credentials.

 3 - Request an API key: Navigate to the section that manages APIs, usually found under "Developer" or "API". Request a new API key by filling out the request form and providing the requested information.

 4 - Fill out the request form: Complete the API key request form, including your name, organization information (if applicable), and intended use for the API key (e.g. research or software development).

 5 - Accept the terms and conditions: Read and accept the terms and conditions for using the API key.

 6 - Receive your API key: After submitting your request, you will receive a confirmation email containing your new API key.

 7 - Configure the environment variable: Once you have the API key, configure it as an environment variable in your operating system. Name your API key NVD_API_KEY to allow the tool to access it.


Once these procedures have been completed, you can use the program, which offers an overview of its features:

 1 - Research Section: Here you can enter a string to search for CVEs that best match your criteria. By default the year of the CVEs will only be 2021. You can change it if you want or use the advanced search
 
 2 - Advance Research Section: More advanced search

 3 - NVD Result: This section displays all the CVEs found along with their information, including the associated CWE, CVSS 2.0 and 3.1 scores, ID and description.

 4 - Graphs Section: Graphs are generated here showing the number of CVEs with certain CVSS 2.0 and 3.1 scores, the distribution of CVEs by year, and the CVE count for each individual CWE.

 5 - Filtered Result Section: You can filter the results in the previous section by String Vector, Base Score and Base Severity.

 6 - Export Section: Finally, this section allows you to export the results in various formats including PDF, JSON, XLSX and CSV.'''

    return text
