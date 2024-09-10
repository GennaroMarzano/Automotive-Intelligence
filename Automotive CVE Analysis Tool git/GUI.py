import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
import requests
from bs4 import BeautifulSoup
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from threading import Thread
import NVD
import Grafici
import Read
from Export import export_to_pdf, export_to_json, export_to_csv, export_to_excel


class CVEAnalysisTool(tk.Tk):

    def __init__(self):
        super().__init__()

        self.date_normal_research_text = None
        self.cvssV3Severity_combobox = None
        self.cvssV2Severity_combobox = None
        self.cveTag_combobox = None
        self.advance_query_text = None
        self.cweId_text = None
        self.sourceIdentifier_text = None
        self.cvssV3Severity_text = None
        self.cvssV3Metrics_text = None
        self.cvssV2Severity_text = None
        self.cvssV2Metrics_text = None
        self.cveTag_text = None
        self.cpe_text = None
        self.date_text = None
        self.result_nvd = None
        self.filtered_text = None
        self.gs = None
        self.canvas = None
        self.fig = None
        self.base_severity_combobox = None
        self.base_score_entry = None
        self.vector_string_entry = None
        self.nvd_text = None
        self.query_text = None
        self.read_me_text = None
        self.export_format_combobox = None
        self.title("CVE Analysis Tool")
        self.geometry("1200x800")
        self.cve_data = []

        self.create_widgets()

    def create_widgets(self):
        style = ttk.Style()
        style.configure("TNotebook.Tab", padding=[20, 10], font=('Helvetica', 12, 'bold'))

        notebook = ttk.Notebook(self)
        notebook.pack(expand=1, fill='both')

        query_frame = ttk.Frame(notebook)
        advance_query_frame = ttk.Frame(notebook)
        nvd_frame = ttk.Frame(notebook)
        filter_frame = ttk.Frame(notebook)
        graphs_frame = ttk.Frame(notebook)
        export_frame = ttk.Frame(notebook)
        read_me_frame = ttk.Frame(notebook)

        notebook.add(query_frame, text='Research')
        notebook.add(advance_query_frame, text='Advance Research')
        notebook.add(nvd_frame, text='NVD Result')
        notebook.add(filter_frame, text='Filtered Result')
        notebook.add(graphs_frame, text='Graphs')
        notebook.add(export_frame, text='Export')
        notebook.add(read_me_frame, text="Read Me")

        self.create_query(query_frame)
        self.create_advance_query(advance_query_frame)
        self.create_nvd(nvd_frame)
        self.create_filtered(filter_frame)
        self.create_graphs(graphs_frame)
        self.create_export(export_frame)
        self.create_read_me(read_me_frame)

    def create_graphs(self, frame):
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.fig = plt.figure(figsize=(14, 40))
        self.canvas = FigureCanvasTkAgg(self.fig, scrollable_frame)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.gs = self.fig.add_gridspec(5, 1, hspace=0.7)

    def create_nvd(self, frame):
        self.nvd_text = tk.Text(frame, wrap='word', font=("Helvetica", 12))
        self.nvd_text.pack(expand=1, fill='both', padx=10, pady=10)

        input_frame = tk.Frame(frame)
        input_frame.pack(pady=5)

        vector_string_label = tk.Label(input_frame, text="Vector String:", font=("Helvetica", 16))
        vector_string_label.grid(row=0, column=0, padx=5)
        self.vector_string_entry = tk.Entry(input_frame, font=("Helvetica", 16), width=50)
        self.vector_string_entry.grid(row=0, column=1, padx=5)

        base_score_label = tk.Label(input_frame, text="Base Score:", font=("Helvetica", 16))
        base_score_label.grid(row=1, column=0, padx=5)
        self.base_score_entry = tk.Entry(input_frame, font=("Helvetica", 16))
        self.base_score_entry.grid(row=1, column=1, padx=5)

        base_severity_label = tk.Label(input_frame, text="Base Severity:", font=("Helvetica", 16))
        base_severity_label.grid(row=2, column=0, padx=5)
        self.base_severity_combobox = ttk.Combobox(input_frame, font=("Helvetica", 16),
                                                   values=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.base_severity_combobox.grid(row=2, column=1, padx=5)

        filter_button = tk.Button(input_frame, text="Filtrate CVE", command=self.filter_cve_by_criteria,
                                  font=("Helvetica", 16))
        filter_button.grid(row=3, column=1, pady=10, padx=5)

    def create_query(self, frame):
        query_label = tk.Label(frame, text="Enter your search query", font=("Helvetica", 18))
        query_label.pack(pady=10)

        self.query_text = tk.Entry(frame, font=("Helvetica", 12), width=100)
        self.query_text.pack(pady=20)

        parent_frame = tk.Frame(frame)
        parent_frame.pack(padx=10, pady=10)

        date_frame = tk.Frame(parent_frame)
        date_frame.pack(anchor="center")

        date_label = tk.Label(date_frame,
                              text="Enter the date, ATTENTION! The date must have the format yyyy e.g. 2021, 2022 etc.",
                              font=("Helvetica", 12))
        date_label.pack(side="left", padx=(0, 10), pady=10)

        self.date_normal_research_text = tk.Entry(date_frame, font=("Helvetica", 12), width=15)
        self.date_normal_research_text.pack(side="left", padx=(10, 0), pady=10)

        search_button = tk.Button(frame, text="Search", command=self.search_and_print_cve, font=("Helvetica", 12))
        search_button.pack(pady=10)

    def create_advance_query(self, frame):
        advance_query_label = tk.Label(frame, text="Advanced Search", font=("Helvetica", 18))
        advance_query_label.pack(pady=10)

        query_frame = tk.Frame(frame)
        query_frame.pack(padx=10, pady=10, anchor="w")

        query_label = tk.Label(query_frame, text="Enter your search query", font=("Helvetica", 12))
        query_label.pack(side="left", padx=(0, 10), pady=10)

        self.advance_query_text = tk.Entry(query_frame, font=("Helvetica", 12), width=100)
        self.advance_query_text.pack(side="left", padx=(10, 0), pady=10)

        date_frame = tk.Frame(frame)
        date_frame.pack(padx=10, pady=10, anchor="w")

        date_label = tk.Label(date_frame,
                              text="Enter the date, ATTENTION! The date must have the format yyyy e.g. 2021, 2022 etc.",
                              font=("Helvetica", 12))
        date_label.pack(side="left", padx=(0, 10), pady=10)

        self.date_text = tk.Entry(date_frame, font=("Helvetica", 12), width=15)
        self.date_text.pack(side="left", padx=(10, 0), pady=10)

        cpe_frame = tk.Frame(frame)
        cpe_frame.pack(padx=10, pady=10, anchor="w")

        cpe_label = tk.Label(cpe_frame,
                             text='Enter the cpe es: cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*',
                             font=("Helvetica", 12))
        cpe_label.pack(side="left", padx=(0, 10), pady=10)

        self.cpe_text = tk.Entry(cpe_frame, font=("Helvetica", 12), width=60)
        self.cpe_text.pack(side="left", padx=(10, 0), pady=10)

        cveTag_frame = tk.Frame(frame)
        cveTag_frame.pack(pady=10, anchor="w")

        cveTag_label = tk.Label(cveTag_frame, text='Select the cveTag', font=("Helvetica", 12))
        cveTag_label.pack(side="left", padx=(0, 10))

        self.cveTag_combobox = ttk.Combobox(cveTag_frame, values=["disputed", "unsupported-when-assigned",
                                                                  "exclusively-hosted-service"], font=("Helvetica", 12),
                                            width=40)
        self.cveTag_combobox.pack(side="left", padx=(10, 0))

        cvssV2_frame = tk.Frame(frame)
        cvssV2_frame.pack(padx=10, pady=10, anchor="w")

        cvssV2Metrics_label = tk.Label(cvssV2_frame, text='Enter the V2 vector string here', font=("Helvetica", 12))
        cvssV2Metrics_label.pack(side="left", padx=(0, 10), pady=10)

        self.cvssV2Metrics_text = tk.Entry(cvssV2_frame, font=("Helvetica", 12), width=40)
        self.cvssV2Metrics_text.pack(side="left", padx=(10, 0), pady=10)

        cvssV2_frame = tk.Frame(frame)
        cvssV2_frame.pack(pady=10, anchor="w")

        cvssV2Severity_label = tk.Label(cvssV2_frame, text='Select the V2 severity', font=("Helvetica", 12))
        cvssV2Severity_label.pack(side="left", padx=(10, 0), pady=10)

        self.cvssV2Severity_combobox = ttk.Combobox(cvssV2_frame, values=["Low", "Medium", "High", "Critical"],
                                                    font=("Helvetica", 12), width=15)
        self.cvssV2Severity_combobox.pack(side="left", padx=(0, 10), pady=10)

        cvssV3_frame = tk.Frame(frame)
        cvssV3_frame.pack(padx=10, pady=10, anchor="w")

        cvssV3Metrics_label = tk.Label(cvssV3_frame, text='Enter the V3.1 vector string here', font=("Helvetica", 12))
        cvssV3Metrics_label.pack(side="left", padx=(0, 10), pady=10)

        self.cvssV3Metrics_text = tk.Entry(cvssV3_frame, font=("Helvetica", 12), width=40)
        self.cvssV3Metrics_text.pack(side="left", padx=(10, 0), pady=10)

        cvssV3_frame = tk.Frame(frame)
        cvssV3_frame.pack(pady=10, anchor="w")

        cvssV3Severity_label = tk.Label(cvssV3_frame, text='Select the V3.1 severity', font=("Helvetica", 12))
        cvssV3Severity_label.pack(side="left", padx=(10, 0), pady=10)

        self.cvssV3Severity_combobox = ttk.Combobox(cvssV3_frame, values=["Low", "Medium", "High", "Critical"],
                                                    font=("Helvetica", 12), width=15)
        self.cvssV3Severity_combobox.pack(side="left", padx=(0, 10), pady=10)

        cweId_frame = tk.Frame(frame)
        cweId_frame.pack(padx=10, pady=10, anchor="w")

        cweId_label = tk.Label(cweId_frame, text='Enter the cwe id es: CWE-287', font=("Helvetica", 12))
        cweId_label.pack(side="left", padx=(0, 10), pady=10)

        self.cweId_text = tk.Entry(cweId_frame, font=("Helvetica", 12), width=15)
        self.cweId_text.pack(side="left", padx=(10, 0), pady=10)

        sourceIdentifier_frame = tk.Frame(frame)
        sourceIdentifier_frame.pack(padx=10, pady=10, anchor="w")

        sourceIdentifier_label = tk.Label(sourceIdentifier_frame, text='Enter the organization es: cve@mitre.org',
                                          font=("Helvetica", 12))
        sourceIdentifier_label.pack(side="left", padx=(0, 10), pady=10)

        self.sourceIdentifier_text = tk.Entry(sourceIdentifier_frame, font=("Helvetica", 12), width=25)
        self.sourceIdentifier_text.pack(side="left", padx=(10, 0), pady=10)

        search_button = tk.Button(frame, text="Search", command=self.search_and_print_cve, font=("Helvetica", 12))
        search_button.pack(pady=10)

    def create_read_me(self, frame):
        query_label = tk.Label(frame, text=Read.text_to_read(), font=("Helvetica", 14), anchor='w', justify='left')
        query_label.pack(pady=10, anchor='w')

    def create_filtered(self, frame):
        self.filtered_text = tk.Text(frame, wrap='word', font=("Helvetica", 12))
        self.filtered_text.pack(expand=1, fill='both', padx=10, pady=10)

    def search_and_print_cve(self):


        # Funzione per eseguire la ricerca e aggiornare l'interfaccia
        def run_search():
            if self.advance_query_text.get():
                # Mostrare l'icona di caricamento subito sotto il bottone di ricerca
                loading_label = tk.Label(self, text="This operation will take some time...", font=("Helvetica", 12))
                loading_label.pack(pady=10,
                                   before=self.advance_query_text)
                search_query = self.advance_query_text.get()
                date = self.date_text.get() if self.date_text.get() else ''
                cpe = self.cpe_text.get() if self.cpe_text.get() else ''
                cveTag = self.cveTag_combobox.get() if self.cvssV2Metrics_text.get() else ''  # Ottieni il valore selezionato dal combobox
                cvssV2Metrics = self.cvssV2Metrics_text.get() if self.cvssV2Metrics_text.get() else ''
                cvssV2Severity = self.cvssV2Severity_combobox.get() if self.cvssV2Severity_text.get() else ''
                cvssV3Metrics = self.cvssV3Metrics_text.get() if self.cvssV3Metrics_text.get() else ''
                cvssV3Severity = self.cvssV3Severity_combobox.get() if self.cvssV3Severity_text.get() else ''
                cweId = self.cweId_text.get() if self.cweId_text.get() else ''
                sourceIdentifier = self.sourceIdentifier_text.get() if self.sourceIdentifier_text.get() else ''

                self.results_nvd = NVD.query_nvd_database_advance(search_query, date, cpe, cveTag, cvssV2Metrics, cvssV2Severity,
                                                         cvssV3Metrics, cvssV3Severity, cweId, sourceIdentifier)
                self.advance_query_text.delete(0, tk.END)  # Cancella il testo dopo la ricerca
            else:
                # Mostrare l'icona di caricamento subito sotto il bottone di ricerca
                loading_label = tk.Label(self, text="This operation will take some time...", font=("Helvetica", 12))
                loading_label.pack(pady=10,
                                   before=self.query_text)  # Usa 'before' per posizionare il label subito sotto
                search_query = self.query_text.get()
                date = self.date_normal_research_text.get()
                self.result_nvd = NVD.query_nvd_database(search_query, date)

            # Funzione per aggiornare l'interfaccia grafica con i risultati
            def update_ui():
                if self.advance_query_text.get():
                    loading_label.pack_forget()  # Rimuovere l'icona di caricamento
                    self.nvd_text.delete(1.0, tk.END)  # Cancellare il testo precedente
                else:
                    loading_label.pack_forget()  # Rimuovere l'icona di caricamento
                self.nvd_text.delete(1.0, tk.END)  # Cancellare il testo precedente

                self.nvd_text.delete(1.0, tk.END)  # Clear previous results
                self.cve_data = []

                if self.result_nvd:
                    for result in self.result_nvd:
                        cve = result['cve']
                        cve_id = cve['id']
                        description = cve['descriptions'][0]['value']
                        try:
                            cwe_ids = [weakness['description'][0].get('value') for weakness in cve.get('weaknesses', [])
                                       if
                                       weakness['description'][0].get('value').startswith('CWE')]
                        except KeyError:
                            cwe_ids = "No Info"
                        cwe_description, cwe_url = get_cwe_descriptions(cwe_ids)

                        # Raccogli i dati delle CVE
                        cve_entry = {
                            'id': cve_id,
                            'description': description,
                            'cwe_ids': cwe_ids,
                            'cvss2': None,
                            'cvss3': None,
                            'year': cve['published'][0:4],
                            'cwe_description': cwe_description,
                            'cwe_url': cwe_url
                        }

                        print_bold(self.nvd_text, "  - CVE ID: ")
                        self.nvd_text.insert(tk.END, f"{cve_id}\n")
                        print_bold(self.nvd_text, "  - Description: ")
                        self.nvd_text.insert(tk.END, f"{description}\n\n")
                        print_bold(self.nvd_text, "  - CWE IDs: ")
                        self.nvd_text.insert(tk.END, f"{cwe_ids}\n")
                        for cwe in cwe_ids:
                            print_bold(self.nvd_text, f"  - {cwe}: ")
                            self.nvd_text.insert(tk.END, f"{cwe_description[cwe]}\n")
                            print_bold(self.nvd_text, "  - More Info: ")
                            self.nvd_text.insert(tk.END, f"{cwe_url[cwe]}\n\n")

                        print_bold(self.nvd_text, "  - CVSS v2.0 Metrics: ")
                        self.nvd_text.insert(tk.END, "\n\n")

                        try:
                            cvss_v2_base_score = cve.get('metrics', {}).get('cvssMetricV2', [])[0].get('cvssData', {})
                            cvss_v2 = cve.get('metrics', {}).get('cvssMetricV2', [])[0]
                            self.nvd_text.insert(tk.END, "  - Base Severity: ")
                            print_colored_severity(self.nvd_text, cvss_v2['baseSeverity'])
                            self.nvd_text.insert(tk.END, "\n")
                            self.nvd_text.insert(tk.END, f"  - Base Score: {cvss_v2_base_score['baseScore']}\n")
                            self.nvd_text.insert(tk.END,
                                                 f"  - Exploitability Score: {cvss_v2['exploitabilityScore']}\n")
                            self.nvd_text.insert(tk.END, f"  - Impact Score: {cvss_v2['impactScore']}\n")
                            self.nvd_text.insert(tk.END, f"  - Ac Insuf Info: {cvss_v2['acInsufInfo']}\n")
                            self.nvd_text.insert(tk.END, f"  - Obtain All Privilege: {cvss_v2['obtainAllPrivilege']}\n")
                            self.nvd_text.insert(tk.END,
                                                 f"  - Obtain User Privilege: {cvss_v2['obtainUserPrivilege']}\n")
                            self.nvd_text.insert(tk.END,
                                                 f"  - Obtain Other Privilege: {cvss_v2['obtainOtherPrivilege']}\n")
                            self.nvd_text.insert(tk.END,
                                                 f"  - User Interaction Required: {cvss_v2['userInteractionRequired']}\n")
                            self.nvd_text.insert(tk.END, "\n\n")
                            print_bold(self.nvd_text, "  - CVSS v2.0 Data: ")
                            self.nvd_text.insert(tk.END, "\n\n")

                            cvss_v2 = cvss_v2.get('cvssData', {})  # Può variare a seconda del formato
                            cve_entry['cvss2'] = cvss_v2['baseScore']
                            self.nvd_text.insert(tk.END, f"  - Vector String: {cvss_v2['vectorString']}\n")
                            self.nvd_text.insert(tk.END, f"  - Access Vector: {cvss_v2['accessVector']}\n")
                            self.nvd_text.insert(tk.END, f"  - Access Complexity: {cvss_v2['accessComplexity']}\n")
                            self.nvd_text.insert(tk.END, f"  - Authentication: {cvss_v2['authentication']}\n")
                            self.nvd_text.insert(tk.END,
                                                 f"  - Confidentiality Impact: {cvss_v2['confidentialityImpact']}\n")
                            self.nvd_text.insert(tk.END, f"  - Integrity Impact: {cvss_v2['integrityImpact']}\n")
                            self.nvd_text.insert(tk.END, f"  - Availability Impact: {cvss_v2['availabilityImpact']}\n")
                        except IndexError:
                            cve_entry['cvss2'] = None
                            self.nvd_text.insert(tk.END, 'No Info\n')

                        self.nvd_text.insert(tk.END, "\n\n")
                        print_bold(self.nvd_text, "  - CVSS v3.1 Metrics: ")
                        self.nvd_text.insert(tk.END, "\n\n")

                        try:
                            cvss_v3 = cve.get('metrics', {}).get('cvssMetricV31', [])[0]
                            self.nvd_text.insert(tk.END,
                                                 f"  - Exploitability Score: {cvss_v3['exploitabilityScore']}\n")
                            self.nvd_text.insert(tk.END, f"  - Impact Score: {cvss_v3['impactScore']}\n")

                            self.nvd_text.insert(tk.END, "\n\n")
                            print_bold(self.nvd_text, "  - CVSS v3.1 Data: ")
                            self.nvd_text.insert(tk.END, "\n\n")

                            cvss_v3 = cvss_v3.get('cvssData', {})  # Può variare a seconda del formato
                            cve_entry['cvss3'] = cvss_v3['baseScore']
                            self.nvd_text.insert(tk.END, "  - Base Severity: ")
                            print_colored_severity(self.nvd_text, cvss_v3['baseSeverity'])
                            self.nvd_text.insert(tk.END, "\n")
                            self.nvd_text.insert(tk.END, f"  - Base Score: {cvss_v3['baseScore']}\n")
                            self.nvd_text.insert(tk.END, f"  - Vector String: {cvss_v3['vectorString'][9:]}\n")
                            self.nvd_text.insert(tk.END, f"  - Attack Vector: {cvss_v3['attackVector']}\n")
                            self.nvd_text.insert(tk.END, f"  - Attack Complexity: {cvss_v3['attackComplexity']}\n")
                            self.nvd_text.insert(tk.END, f"  - Privileges Required: {cvss_v3['privilegesRequired']}\n")
                            self.nvd_text.insert(tk.END, f"  - User Interaction: {cvss_v3['userInteraction']}\n")
                            self.nvd_text.insert(tk.END, f"  - Scope: {cvss_v3['scope']}\n")
                            self.nvd_text.insert(tk.END,
                                                 f"  - Confidentiality Impact: {cvss_v3['confidentialityImpact']}\n")
                            self.nvd_text.insert(tk.END, f"  - Integrity Impact: {cvss_v3['integrityImpact']}\n")
                            self.nvd_text.insert(tk.END, f"  - Availability Impact: {cvss_v3['availabilityImpact']}\n")
                            self.nvd_text.insert(tk.END,
                                                 '---------------------------------------------------------------'
                                                 '---------------------------------------------------------------------'
                                                 '---------------------------------------------------------------------'
                                                 '------------------------------------------------------------------\n')
                        except IndexError:
                            self.nvd_text.insert(tk.END, 'No Info\n')
                            self.nvd_text.insert(tk.END,
                                                 '--------------------------------------------------------------'
                                                 '--------------------------------------------------------------------'
                                                 '--------------------------------------------------------------------'
                                                 '-----------------------------------------------------------------\n')
                            cve_entry['cvss3'] = None
                        self.cve_data.append(cve_entry)
                        self.nvd_text.insert(tk.END, "\n")
                else:
                    self.nvd_text.insert(tk.END, "No results found\n")
                self.display_graphs()

            self.after(0, update_ui)

        # Eseguire la ricerca in un thread separato
        Thread(target=run_search).start()

    def display_graphs(self):
        self.fig.clear()  # Pulisce la figura esistente
        self.gs = self.fig.add_gridspec(5, 1)  # Reimposta la griglia dei subplot

        Grafici.plot_cvss_distribution(self.fig, self.gs, self.cve_data)
        Grafici.plot_cve_by_year(self.fig, self.gs, self.cve_data)
        Grafici.plot_cve_by_cwe(self.fig, self.gs, self.cve_data)

        self.fig.subplots_adjust(hspace=0.5)  # Aggiunge spaziatura verticale tra i grafici

        self.canvas.draw()  # Ridisegna la Canvas con i nuovi grafici

    def export_cve_data(self):
        # Funzione per esportare i dati delle CVE

        format_to_export = self.export_format_combobox.get()  # Ottiene il formato selezionato

        if format_to_export == "PDF":
            export_to_pdf(self.cve_data)
        elif format_to_export == "CSV":
            export_to_csv(self.cve_data)
        elif format_to_export == "JSON":
            export_to_json(self.cve_data)
        else:
            export_to_excel(self.cve_data)

    def create_export(self, frame):
        # Add an empty label for spacing
        spacing_label = tk.Label(frame, text="")
        spacing_label.pack(pady=20)

        # Add an empty label for spacing
        spacing_label = tk.Label(frame, text="")
        spacing_label.pack(pady=20)

        export_label = tk.Label(frame, text="Select format for export:", font=("Helvetica", 20))
        export_label.pack(pady=10)

        export_options = ["PDF", "CSV", "JSON", "XLSX"]  # Aggiungi qui altri formati se necessario
        self.export_format_combobox = ttk.Combobox(frame, values=export_options, font=("Helvetica", 18))
        self.export_format_combobox.pack(pady=10)

        export_button = tk.Button(frame, text="Export", command=self.export_cve_data, font=("Helvetica", 18))
        export_button.pack(pady=10)

    def filter_cve_by_criteria(self):
        vector_string_value = self.vector_string_entry.get().strip()
        base_score_value = self.base_score_entry.get().strip()
        base_severity_value = self.base_severity_combobox.get().strip()

        filtered_results = []
        for result in self.result_nvd:
            metrics = result['cve'].get('metrics', {})

            # Controlla se esistono dati CVSS v2
            cvss_v2_metrics = metrics.get('cvssMetricV2', [])
            cvss_v2 = metrics.get('cvssMetricV2', [])[0]
            for metric in cvss_v2_metrics:
                cvss_data = metric.get('cvssData', {})
                vector_string_matches = ('vectorString' in cvss_data and vector_string_value in cvss_data[
                    'vectorString']) if vector_string_value else True
                base_score_matches = (base_score_value and cvss_data.get('baseScore') == float(
                    base_score_value)) if base_score_value else True
                base_severity_matches = (base_severity_value and cvss_v2[
                    'baseSeverity'] == base_severity_value) if base_severity_value else True

                if vector_string_matches and base_score_matches and base_severity_matches:
                    filtered_results.append(result)
                    break  # Trovata una corrispondenza, non serve continuare a cercare in questo risultato

            # Controlla se esistono dati CVSS v3
            cvss_v3_metrics = metrics.get('cvssMetricV31', [])
            for metric in cvss_v3_metrics:
                cvss_data = metric.get('cvssData', {})
                vector_string_matches = ('vectorString' in cvss_data and vector_string_value in cvss_data[
                    'vectorString']) if vector_string_value else True
                base_score_matches = (base_score_value and cvss_data.get('baseScore') == float(
                    base_score_value)) if base_score_value else True
                base_severity_matches = (base_severity_value and cvss_data.get(
                    'baseSeverity') == base_severity_value) if base_severity_value else True

                if vector_string_matches and base_score_matches and base_severity_matches:
                    filtered_results.append(result)
                    break  # Trovata una corrispondenza, non serve continuare a cercare in questo risultato

        self.display_filter_result(filtered_results)

    def display_filter_result(self, results):
        self.filtered_text.delete(1.0, tk.END)  # Clear previous results
        cve_data = []

        if results:
            for result in results:
                cve = result['cve']
                cve_id = cve['id']
                description = cve['descriptions'][0]['value']
                try:
                    cwe_ids = [weakness['description'][0].get('value') for weakness in cve.get('weaknesses', []) if
                               weakness['description'][0].get('value').startswith('CWE')]
                except KeyError:
                    cwe_ids = "No Info"
                cwe_description, cwe_url = get_cwe_descriptions(cwe_ids)

                # Raccogli i dati delle CVE
                cve_entry = {
                    'id': cve_id,
                    'description': description,
                    'cwe_ids': cwe_ids,
                    'cvss2': None,
                    'cvss3': None,
                    'year': cve['published'][0:4],
                    'cwe_description': cwe_description,
                    'cwe_url': cwe_url
                }

                print_bold(self.filtered_text, "  - CVE ID: ")
                self.filtered_text.insert(tk.END, f"{cve_id}\n")
                print_bold(self.filtered_text, "  - Description: ")
                self.filtered_text.insert(tk.END, f"{description}\n\n")
                print_bold(self.filtered_text, "  - CWE IDs: ")
                self.filtered_text.insert(tk.END, f"{cwe_ids}\n")
                for cwe in cwe_ids:
                    print_bold(self.filtered_text, f"  - {cwe}: ")
                    self.filtered_text.insert(tk.END, f"{cwe_description[cwe]}\n")
                    print_bold(self.filtered_text, "  - More Info: ")
                    self.filtered_text.insert(tk.END, f"{cwe_url[cwe]}\n\n")

                print_bold(self.filtered_text, "  - CVSS v2.0 Metrics: ")
                self.filtered_text.insert(tk.END, "\n\n")

                try:
                    cvss_v2_base_score = cve.get('metrics', {}).get('cvssMetricV2', [])[0].get('cvssData', {})
                    cvss_v2 = cve.get('metrics', {}).get('cvssMetricV2', [])[0]
                    self.filtered_text.insert(tk.END, "  - Base Severity: ")
                    print_colored_severity(self.filtered_text, cvss_v2['baseSeverity'])
                    self.filtered_text.insert(tk.END, "\n")
                    self.filtered_text.insert(tk.END, f"  - Base Score: {cvss_v2_base_score['baseScore']}\n")
                    self.filtered_text.insert(tk.END, f"  - Exploitability Score: {cvss_v2['exploitabilityScore']}\n")
                    self.filtered_text.insert(tk.END, f"  - Impact Score: {cvss_v2['impactScore']}\n")
                    self.filtered_text.insert(tk.END, f"  - Ac Insuf Info: {cvss_v2['acInsufInfo']}\n")
                    self.filtered_text.insert(tk.END, f"  - Obtain All Privilege: {cvss_v2['obtainAllPrivilege']}\n")
                    self.filtered_text.insert(tk.END, f"  - Obtain User Privilege: {cvss_v2['obtainUserPrivilege']}\n")
                    self.filtered_text.insert(tk.END,
                                              f"  - Obtain Other Privilege: {cvss_v2['obtainOtherPrivilege']}\n")
                    self.filtered_text.insert(tk.END,
                                              f"  - User Interaction Required: {cvss_v2['userInteractionRequired']}\n")
                    self.filtered_text.insert(tk.END, "\n\n")
                    print_bold(self.filtered_text, "  - CVSS v2.0 Data: ")
                    self.filtered_text.insert(tk.END, "\n\n")

                    cvss_v2 = cvss_v2.get('cvssData', {})  # Può variare a seconda del formato
                    cve_entry['cvss2'] = cvss_v2['baseScore']
                    self.filtered_text.insert(tk.END, f"  - Vector String: {cvss_v2['vectorString']}\n")
                    self.filtered_text.insert(tk.END, f"  - Access Vector: {cvss_v2['accessVector']}\n")
                    self.filtered_text.insert(tk.END, f"  - Access Complexity: {cvss_v2['accessComplexity']}\n")
                    self.filtered_text.insert(tk.END, f"  - Authentication: {cvss_v2['authentication']}\n")
                    self.filtered_text.insert(tk.END,
                                              f"  - Confidentiality Impact: {cvss_v2['confidentialityImpact']}\n")
                    self.filtered_text.insert(tk.END, f"  - Integrity Impact: {cvss_v2['integrityImpact']}\n")
                    self.filtered_text.insert(tk.END, f"  - Availability Impact: {cvss_v2['availabilityImpact']}\n")
                except IndexError:
                    cve_entry['cvss2'] = None
                    self.filtered_text.insert(tk.END, 'No Info\n')

                self.filtered_text.insert(tk.END, "\n\n")
                print_bold(self.filtered_text, "  - CVSS v3.1 Metrics: ")
                self.filtered_text.insert(tk.END, "\n\n")

                try:
                    cvss_v3 = cve.get('metrics', {}).get('cvssMetricV31', [])[0]
                    self.filtered_text.insert(tk.END, f"  - Exploitability Score: {cvss_v3['exploitabilityScore']}\n")
                    self.filtered_text.insert(tk.END, f"  - Impact Score: {cvss_v3['impactScore']}\n")

                    self.filtered_text.insert(tk.END, "\n\n")
                    print_bold(self.filtered_text, "  - CVSS v3.1 Data: ")
                    self.filtered_text.insert(tk.END, "\n\n")

                    cvss_v3 = cvss_v3.get('cvssData', {})  # Può variare a seconda del formato
                    cve_entry['cvss3'] = cvss_v3['baseScore']
                    self.filtered_text.insert(tk.END, "  - Base Severity: ")
                    print_colored_severity(self.filtered_text, cvss_v3['baseSeverity'])
                    self.filtered_text.insert(tk.END, "\n")
                    self.filtered_text.insert(tk.END, f"  - Base Score: {cvss_v3['baseScore']}\n")
                    self.filtered_text.insert(tk.END, f"  - Vector String: {cvss_v3['vectorString'][9:]}\n")
                    self.filtered_text.insert(tk.END, f"  - Attack Vector: {cvss_v3['attackVector']}\n")
                    self.filtered_text.insert(tk.END, f"  - Attack Complexity: {cvss_v3['attackComplexity']}\n")
                    self.filtered_text.insert(tk.END, f"  - Privileges Required: {cvss_v3['privilegesRequired']}\n")
                    self.filtered_text.insert(tk.END, f"  - User Interaction: {cvss_v3['userInteraction']}\n")
                    self.filtered_text.insert(tk.END, f"  - Scope: {cvss_v3['scope']}\n")
                    self.filtered_text.insert(tk.END,
                                              f"  - Confidentiality Impact: {cvss_v3['confidentialityImpact']}\n")
                    self.filtered_text.insert(tk.END, f"  - Integrity Impact: {cvss_v3['integrityImpact']}\n")
                    self.filtered_text.insert(tk.END, f"  - Availability Impact: {cvss_v3['availabilityImpact']}\n")
                    self.filtered_text.insert(tk.END, '-------------------------------------------------------------'
                                                      '-------------------------------------------------------------------'
                                                      '-------------------------------------------------------------------'
                                                      '-----------------------------------------------------------------'
                                                      '-------\n')
                except IndexError:
                    self.filtered_text.insert(tk.END, 'No Info\n')
                    self.filtered_text.insert(tk.END, '-------------------------------------------------------------'
                                                      '-------------------------------------------------------------------'
                                                      '-------------------------------------------------------------------'
                                                      '----------------------------------------------------------------'
                                                      '-------\n')
                    cve_entry['cvss3'] = None
                cve_data.append(cve_entry)
                self.filtered_text.insert(tk.END, "\n")
        else:
            self.filtered_text.insert(tk.END, "No results found\n")


def get_cwe_descriptions(cwe_ids):
    cwe_descriptions = {}  # Dizionario per memorizzare le descrizioni delle CWE
    cwe_url = {}
    for cwe_id in cwe_ids:
        url = f"https://cwe.mitre.org/data/definitions/{cwe_id[4:]}.html"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                description_element = soup.find('div', class_='indent')
                description = description_element.get_text(
                    strip=True) if description_element else "Descrizione non disponibile."
                cwe_descriptions[cwe_id] = description  # Associa la descrizione alla CWE nel dizionario
                cwe_url[cwe_id] = url
            else:
                cwe_descriptions[cwe_id] = None
                cwe_url[cwe_id] = None
        except Exception as e:
            print(f"Errore durante la richiesta HTTP: {e}")
    return cwe_descriptions, cwe_url


def print_colored_severity(text_widget, severity):
    colors = {
        'LOW': 'green',
        'MEDIUM': 'orange',
        'HIGH': 'red',
        'CRITICAL': 'darkred'
    }
    color = colors.get(severity, 'black')
    text_widget.tag_configure(severity, foreground=color)
    text_widget.insert(tk.END, severity, severity)


def print_bold(text_widget, text):
    text_widget.tag_configure('bold', font=('Helvetica', 12, 'bold'))
    text_widget.insert(tk.END, text, 'bold')


if __name__ == "__main__":
    app = CVEAnalysisTool()
    app.mainloop()
