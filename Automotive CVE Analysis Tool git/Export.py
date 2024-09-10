from fpdf import FPDF
import xlsxwriter
from tkinter import filedialog, messagebox
import json
import csv


class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'CVE Report', 0, 1, 'C')

    def chapter_title(self, cve_id):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, f'CVE ID: {cve_id}', 0, 1, 'L')
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 12)
        self.multi_cell(0, 10, body)
        self.ln()


def export_to_pdf(cve_data):
    file_path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                             filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")])
    if not file_path:
        return  # User cancelled the dialog

    pdf = PDF()
    pdf.add_page()

    for cve in cve_data:
        pdf.chapter_title(cve['id'])
        body = f"Description: {cve['description']}\n"
        body += f"CWE IDs: {', '.join(cve['cwe_ids'])}\n"
        if cve['cvss2']:
            body += f"CVSS v2.0 Base Score: {cve['cvss2']}\n"
        else:
            body += "CVSS v2.0 Base Score: No Info\n"
        if cve['cvss3']:
            body += f"CVSS v3.0 Base Score: {cve['cvss3']}\n"
        else:
            body += "CVSS v3.0 Base Score: No Info\n"
        body += f"Published Year: {cve['year']}\n"
        pdf.chapter_body(body)

    try:
        pdf.output(file_path)
        messagebox.showinfo("Success", f"CVE data was successfully exported to '{file_path}'.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving the file: {e}")


def export_to_json(cve_data):
    # Open a file dialog to select where to save the file
    file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
    if not file_path:
        return  # User cancelled the dialog

    try:
        with open(file_path, 'w') as file:
            json.dump(cve_data, file, indent=4)
        messagebox.showinfo("Success", f"CVE data was successfully exported to '{file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving the file: {e}")


def Ep(score):
    if 0.1 <= score <= 3.9:
        return "LOW"
    elif 4.0 <= score <= 6.9:
        return "MEDIUM"
    elif 7.0 <= score <= 8.9:
        return "HIGH"
    elif 9.0 <= score <= 10.0:
        return "CRITICAL"
    else:
        return "No Info"


def export_to_csv(cve_data):
    # Apri un dialogo per chiedere all'utente dove salvare il file
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if not file_path:
        return  # L'utente ha annullato il dialogo

    # Controlla che ci siano dati da esportare
    if not cve_data:
        messagebox.showerror("Error", "Nessun dato disponibile per l'esportazione.")
        return

    # Definisci i nomi delle colonne del CSV
    fieldnames = ['CVE ID', 'Description', 'CWE IDs', 'CVSS Base Severity', 'CVSS Base Score']

    try:
        with open(file_path, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)

            # Scrivi l'intestazione del CSV
            writer.writeheader()

            # Scrivi ogni riga dei dati delle CVE
            for cve_entry in cve_data:
                # Inizializza le variabili per CVSS
                base_score = None
                base_severity = "No Info"

                # Verifica se i dati CVSS v3 sono presenti
                if 'cvss3' in cve_entry and cve_entry['cvss3'] is not None:
                    base_score = cve_entry['cvss3']
                elif 'cvss2' in cve_entry and cve_entry['cvss2'] is not None:
                    base_score = cve_entry['cvss2']

                # Determina la gravità basata sul punteggio CVSS
                if base_score is not None:
                    base_severity = get_cvss_severity(base_score)

                writer.writerow({
                    'CVE ID': cve_entry['id'],
                    'Description': cve_entry['description'],
                    'CWE IDs': ', '.join(cve_entry['cwe_ids']),
                    'CVSS Base Severity': base_severity,
                    'CVSS Base Score': base_score if base_score is not None else 'No Info'
                })

        messagebox.showinfo("Success", f"CVE data was successfully exported to '{file_path}'.")

    except IOError as e:
        messagebox.showerror("Error", f"An error occurred while saving the file: {e}")


def export_to_excel(cve_data):
    # Apri un dialogo per chiedere all'utente dove salvare il file
    file_path = filedialog.asksaveasfilename(defaultextension=".xlsx",
                                             filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")])
    if not file_path:
        return  # L'utente ha annullato il dialogo

    # Controlla che ci siano dati da esportare
    if not cve_data:
        messagebox.showerror("Error", "Nessun dato disponibile per l'esportazione.")
        return

    try:
        # Crea un file Excel e un foglio di lavoro
        workbook = xlsxwriter.Workbook(file_path)
        worksheet = workbook.add_worksheet()

        # Definisci i nomi delle colonne
        headers = ['CVE ID', 'Description', 'CWE IDs', 'CVSS Base Severity', 'CVSS Base Score']
        for col_num, header in enumerate(headers):
            worksheet.write(0, col_num, header)

        # Scrivi ogni riga dei dati delle CVE
        for row_num, cve_entry in enumerate(cve_data, start=1):
            # Inizializza le variabili per CVSS
            base_score = None
            base_severity = "No Info"

            # Verifica se i dati CVSS v3 sono presenti
            if 'cvss3' in cve_entry and cve_entry['cvss3'] is not None:
                base_score = cve_entry['cvss3']
            elif 'cvss2' in cve_entry and cve_entry['cvss2'] is not None:
                base_score = cve_entry['cvss2']

            # Determina la gravità basata sul punteggio CVSS
            if base_score is not None:
                base_severity = get_cvss_severity(base_score)

            # Scrivi i dati nel foglio di lavoro
            worksheet.write(row_num, 0, cve_entry['id'])
            worksheet.write(row_num, 1, cve_entry['description'])
            worksheet.write(row_num, 2, ', '.join(cve_entry['cwe_ids']))
            worksheet.write(row_num, 3, base_severity)
            worksheet.write(row_num, 4, base_score if base_score is not None else 'No Info')

        # Chiudi il file Excel
        workbook.close()
        messagebox.showinfo("Success", f"CVE data was successfully exported to '{file_path}'.")

    except IOError as e:
        messagebox.showerror("Error", f"An error occurred while saving the file: {e}")
