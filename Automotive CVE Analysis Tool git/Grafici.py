import numpy as np


def plot_cvss_distribution(fig, gs, cve_data):
    cvss_2_scores = [cve['cvss2'] for cve in cve_data if cve['cvss2'] is not None]
    cvss_3_scores = [cve['cvss3'] for cve in cve_data if cve['cvss3'] is not None]

    ax0 = fig.add_subplot(gs[0, :])
    ax0.hist(cvss_2_scores, bins=80, color='blue', alpha=0.7, edgecolor='black')  # 20 bins for better visualization
    ax0.set_title('Distribution of CVSS 2.0 scores')
    ax0.set_xlabel('CVSS Score 2.0')
    ax0.set_ylabel('CVE number')

    # Set X-axis to increment by 0.5
    ax0.set_xticks(np.arange(0.0, 10.5, 0.5))

    # Set Y-axis to increment by 1
    ax0.set_yticks(np.arange(0, max(len(cvss_2_scores), 10) + 1, 1))
    ax0.set_ylim(0, max(len(cvss_2_scores), 10) + 1)

    ax1 = fig.add_subplot(gs[1, :])
    ax1.hist(cvss_3_scores, bins=80, color='green', alpha=0.7, edgecolor='black')  # 20 bins for better visualization
    ax1.set_title('Distribution of CVSS 3.1 scores')
    ax1.set_xlabel('CVSS Score 3.1')
    ax1.set_ylabel('CVE number')

    # Set X-axis to increment by 0.5
    ax1.set_xticks(np.arange(0.0, 10.5, 0.5))

    # Set Y-axis to increment by 1
    ax1.set_yticks(np.arange(0, max(len(cvss_3_scores), 10) + 1, 1))
    ax1.set_ylim(0, max(len(cvss_3_scores), 10) + 1)


def plot_cve_by_year(fig, gs, cve_data):
    years = [cve['year'] for cve in cve_data]
    year_counts = {year: years.count(year) for year in set(years)}
    sorted_years = sorted(year_counts.items())

    ax = fig.add_subplot(gs[2, :])
    ax.bar([year for year, count in sorted_years], [count for year, count in sorted_years], color='purple')
    ax.set_title('Number of CVEs per year')
    ax.set_xlabel('Year')
    ax.set_ylabel('CVE number')

    # Set Y-axis to increment by 1
    ax.set_yticks(np.arange(0, max(year_counts.values()) + 1, 1))
    ax.set_ylim(0, max(year_counts.values()) + 1)


def plot_cve_by_cwe(fig, gs, cve_data):
    cwe_ids = []
    cwe_to_cves = {}

    for cve in cve_data:
        if isinstance(cve['cwe_ids'], list):
            for cwe_id in cve['cwe_ids']:
                cwe_ids.append(cwe_id)
                if cwe_id not in cwe_to_cves:
                    cwe_to_cves[cwe_id] = []
                cwe_to_cves[cwe_id].append(cve['id'])

    cwe_counts = {cwe: cwe_ids.count(cwe) for cwe in set(cwe_ids)}
    sorted_cwe_counts = sorted(cwe_counts.items())

    ax1 = fig.add_subplot(gs[3])
    ax1.bar([cwe for cwe, count in sorted_cwe_counts], [count for cwe, count in sorted_cwe_counts], color='red')
    ax1.set_title('Distribution of CVEs for CWE')
    ax1.set_xlabel('ID CWE')
    ax1.set_ylabel('CVE number')
    ax1.set_xticklabels([cwe for cwe, count in sorted_cwe_counts], rotation=90, ha='right')

    # Set Y-axis to increment by 1
    ax1.set_yticks(np.arange(0, max(cwe_counts.values()) + 1, 1))

    ax2 = fig.add_subplot(gs[4])
    ax2.axis('off')
    table_data = [[cwe, ", ".join(cwe_to_cves[cwe])] for cwe, count in sorted_cwe_counts]
    table = ax2.table(cellText=table_data, colLabels=['CWE ID', 'CVE IDs'], loc='center', cellLoc='left')
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.auto_set_column_width([0, 1])

    # Aumenta l'altezza delle righe
    for key, cell in table.get_celld().items():
        cell.set_height(0.10)  # Imposta l'altezza della riga a un valore maggiore