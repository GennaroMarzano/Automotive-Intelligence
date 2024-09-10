import requests
import os
import time


def query_nvd_database(query_string, date, results_per_page=10):
    nvd_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    api_key = os.getenv('NVD_API_KEY')
    if not api_key:
        print("API key not found in environment variables")
        return []

    headers = {
        'apiKey': api_key
    }

    all_results = []
    start_index = 0
    more_results = True  # Variabile per controllare se ci sono più risultati

    while more_results:
        params = {
            'keywordSearch': query_string,
            'pubStartDate': f'{date}-08-04T00:00:00.000',
            'pubEndDate': f'{date}-10-22T00:00:00.000',
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
        response = requests.get(nvd_url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                more_results = False  # Nessun risultato significa che abbiamo finito
            else:
                all_results.extend(vulnerabilities)
                start_index += results_per_page
        else:
            print('Error in API request:', response.status_code)
            break
        time.sleep(5)  # Rispetta il rate limit dell'API

    return all_results


def query_nvd_database_advance(query_string, date, cpe, cveTag, cvssV2Metrics, cvssV2Severity,
                                                        cvssV3Metrics, cvssV3Severity, cweId, sourceIdentifier, results_per_page=10):
    nvd_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    api_key = os.getenv('NVD_API_KEY')
    if not api_key:
        print("API key not found in environment variables")
        return []

    headers = {
        'apiKey': api_key
    }

    all_results = []
    start_index = 0
    more_results = True  # Variabile per controllare se ci sono più risultati

    while more_results:
        params = {
            'cpeName': cpe,
            'cveTag': cveTag,
            'cvssV2Metrics': cvssV2Metrics,
            'cvssV2Severity': cvssV2Severity,
            'cvssV3Metrics': cvssV3Metrics,
            'cvssV3Severity': cvssV3Severity,
            'cweId': cweId,
            'sourceIdentifier': sourceIdentifier,
            'keywordSearch': query_string,
            'pubStartDate': f'{date}-08-04T00:00:00.000',
            'pubEndDate': f'{date}-10-22T00:00:00.000',
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
        response = requests.get(nvd_url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if not vulnerabilities:
                more_results = False  # Nessun risultato significa che abbiamo finito
            else:
                all_results.extend(vulnerabilities)
                start_index += results_per_page
        else:
            print('Error in API request:', response.status_code)
            break
        time.sleep(5)  # Rispetta il rate limit dell'API

    return all_results
