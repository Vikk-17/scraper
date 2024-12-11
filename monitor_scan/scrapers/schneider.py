import asyncio
import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup


class SchneiderScraper:
    __base_url = (
        "https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp"
    )

    def __init__(self, product_names: list, headless: bool = True):
        self.headless = headless
        self.driver = None
        self.product_names = product_names

    def clean_text(self, text):
        """
        Cleans unwanted characters from text.
        """
        if text:
            return (
                text.replace("\u200b", "")
                .replace("\u2022", "")
                .replace("\u00a0", " ")
                .replace("\u2122", "")
                .strip()
            )
        return text

    async def __aenter__(self):
        """
        Asynchronous context manager entry.
        Sets up the Selenium WebDriver for automating the browser.
        """
        chrome_options = Options()
        if self.headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        self.driver = webdriver.Chrome(options=chrome_options)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Asynchronous context manager exit.
        Closes the Selenium WebDriver.
        """
        if self.driver:
            self.driver.quit()

    def scrape_table(self):
        """
        Scrapes the table data from the webpage and cleans it.
        Returns the cleaned data as a JSON string.
        """
        try:
            # Open the website using Selenium WebDriver
            self.driver.get(self.__base_url)

            # Wait for the table to load
            wait = WebDriverWait(self.driver, 10)
            wait.until(EC.presence_of_element_located((By.CLASS_NAME, "se2--table")))

            # Parse the page source with BeautifulSoup
            soup = BeautifulSoup(self.driver.page_source, "html.parser")

            # Locate the table
            table = soup.find("div", class_="se2--table")
            if not table:
                print("Table with class 'se2--table' not found.")
                return None

            # Extract headers from the thead
            headers = []
            thead = table.find("thead")
            if thead:
                header_row = thead.find_all("th")
                headers = [header.text.strip() for header in header_row]

            # Extract rows from the tbody
            rows = []
            tbody = table.find("tbody")
            if tbody:
                table_rows = tbody.find_all("tr")
                for row in table_rows:
                    cols = row.find_all("td", class_="se2-text-normal")
                    row_data = [col.text.strip() for col in cols]
                    if row_data:
                        rows.append(row_data)

            # Clean and structure data into a list of dictionaries
            clean_data = []
            for row in rows:
                row_dict = {}
                for idx, col in enumerate(row):
                    if idx < len(headers):
                        key = headers[idx].strip()
                        value = (
                            col.replace("\u2022", "")
                            .replace("\u200b", " ")
                            .replace("\u00a0", " ")
                            .replace("\u2122", "")
                            .strip()
                        )
                        row_dict[key] = value
                clean_data.append(row_dict)

            return clean_data

        except Exception as e:
            print(f"Error during scraping: {e}")
            return None

    async def run_scraper(self):
        """
        Asynchronous method to scrape the table and filter results based on product names.
        """
        data = await asyncio.to_thread(self.scrape_table)
        filtered_data = []
        if data:
            for product_title in self.product_names:
                for entry in data:
                    if product_title.lower() in entry.get("Title", "").lower():
                        filtered_data.append(
                            {
                                "product_name": entry.get("Title", "Unknown"),
                                "cve_id": entry.get("CVE", "Unknown"),
                                "severity": entry.get("Severity", "Unknown"),
                                "description": entry.get("Description", "No description available."),
                                "last_updated": entry.get("Last updated", "Unknown"),
                                "link": self.__base_url,
                            }
                        )
        return filtered_data




async def main():
    product_lists = [
        "PowerLogic PM5300 Series",
    ]

    async with SchneiderScraper(product_lists) as scraper:
        filtered_result = await scraper.run_scraper()
        if filtered_result:
            print("Filtered results:\n")
            print(json.dumps(filtered_result, indent=4))
        else:
            print("No results found for the provided product titles.")


if __name__ == "__main__":
    asyncio.run(main())