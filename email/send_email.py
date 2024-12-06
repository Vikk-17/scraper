import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from docx import Document
import json
import os
from dotenv import load_dotenv

# take environment variable from .env file
load_dotenv()


class EmailSender:
    """
    To send the email
    :params: It takes user email of particular user
    :output: make the document file and send to the user
    """

    def __init__(self, raw_data:str):
        self.sender_email = os.getenv("SENDER_EMAIL")
        self.sender_password = os.getenv("SENDER_PASSWORD")
        self.subject = "Mail regarding critical vulnerabilities"
        self.body = "Here are your report of vulnerabilities\n"
        try:
            self.obj_data = json.loads(raw_data)
        except Exception as e:
            raise Exception(f"Error while processing the raw data {e}")


    def getEmail(self)-> str:
        """Get the email from the dictionary file"""
        try:
            return (self.obj_data).get("userEmail")
        except Exception as e:
            raise Exception(f"Can't get the user email {e}")

    def format_data(self) -> dict:
        """Get the description and format it"""
        try:
            scan_details_obj = self.obj_data.get("scanDetails")
            output_data = {
                "CVE ID": scan_details_obj.get('cve_id'),
                "Severity": scan_details_obj.get('baseSeverity'),
                "Description": scan_details_obj.get('vulnerabilityDescription'),
                "Mitigation": scan_details_obj.get('Mitigation'),
                "Published Date": scan_details_obj.get('published date'),
                "URL": scan_details_obj.get('url'),
            }

            return output_data

        except Exception as e:
            raise Exception(f"Can't create the format {e}")

    def create_doc(self) -> str:
        """To create the document"""
        try:
            doc = Document()
            doc.add_heading("Details of your product", level=1)
            doc.add_paragraph("\n\nBelow you may find the vulnerabilities\n\n")
            for key, value in (self.format_data()).items():
                doc.add_paragraph(f"{key}: {value}")
            filename = "vuln.docx"
            doc.save(filename)
            return filename
        except Exception as e:
            raise Exception(f"Cann't generate or save file: {e}")

    def send_email(self):
        """To Send the email"""

        try:
            message = MIMEMultipart()
            message["From"] = self.sender_email
            message["To"] = self.getEmail()
            message["Subject"] = self.subject

            # Email body
            message.attach(MIMEText(self.body, "plain"))
            file_to_send = self.create_doc()
            # Attach the file
            with open(file_to_send, "rb") as attachment_file:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment_file.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={file_to_send}")
            message.attach(part)

            # Send the email
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(message)
                print("Email sent successfully!")

        except Exception as e:
            print(f"Error in sending email: {e}")


def main():
    test_data = """{
        "userEmail": "chakraborty7117@gmail.com",
        "scanDetails": {
            "cve_id": "CVE-2024-0001",
            "baseSeverity": "High",
            "vulnerabilityDescription": "Sample vulnerability description.",
            "Mitigation": "Apply patch X.",
            "published date": "2024-11-29",
            "url": "http://example.com"
        }
    }
    """
    try:
        # input_data = sys.stdin.read()
        sendEmail = EmailSender(test_data)
        sendEmail.send_email()

    except Exception as e:
        print("Unexpected error while sending email: {e}")


if __name__ == "__main__":
    main()
