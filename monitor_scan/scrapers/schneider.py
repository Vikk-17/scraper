import asyncio
import json
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup


class SchneiderScraper:

    __base_url = "https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp"

    def __init__(self):
        self.headless = True
        self.driver = None

    def setup_driver(self):
        """
        Sets up the Selenium WebDriver for automating the browser.
        """
        chrome_options = Options()
        if self.headless:
            chrome_options.add_argument("--headless")  # Runs the browser without opening a visible window
        chrome_options.add_argument("--no-sandbox")  # Improve compatibility in certain environments like Docker or CI/CD pipelines
        chrome_options.add_argument("--disable-dev-shm-usage")
        self.driver = webdriver.Chrome(options=chrome_options)

    def scrape_table(self):
        """
        Scrapes the table data from the webpage and cleans it.
        Returns the cleaned data as a JSON string.
        """
        try:
            # Open the website using Selenium WebDriver
            self.driver.get(self.url)

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
                        value = col.replace("\u2022", "").replace("\u200b", " ").replace("\u00a0", " ").replace("\u2122", "").strip()
                        row_dict[key] = value
                clean_data.append(row_dict)

            return clean_data

        except Exception as e:
            print(f"Error during scraping: {e}")
            return None

        finally:
            # Close the WebDriver
            if self.driver:
                self.driver.quit()


async def run_scraper(url, product_titles, headless=True):
    """
    Asynchronous function to run the SchneiderScraper and filter results.
    """
    scraper = SchneiderScraper(url, headless=headless)
    scraper.setup_driver()
    data = await asyncio.to_thread(scraper.scrape_table)
    filtered_data = []
    if data:
        for product_title in product_titles:
            for entry in data:
                if product_title.lower() in entry.get("Title", "").lower():
                    product_name = entry.get("Title", "Unknown")
                    descriptions = entry.get("Description", "No description available.")
                    filtered_data.append({
                        "product_name": product_name,
                        "cve_id": entry.get("CVE", "Unknown"),
                        "last_updated": entry.get("Last updated", "Unknown"),
                        "CSAF": entry.get("CSAF", "Unknown"),
                        "description": descriptions,
                        "link": url,
                    })
    return filtered_data


async def main():
    product_titles = input("Enter the product titles to filter (separated by commas): ").strip().split(',')
    filtered_result = await run_scraper(url, product_titles, headless)
    if filtered_result:
        print("Filtered results:\n")
        print(json.dumps(filtered_result, indent=4))
    else:
        print("No results found for the provided product titles.")


if __name__ == "__main__":
    asyncio.run(main())
