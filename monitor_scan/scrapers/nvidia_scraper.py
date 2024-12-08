import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re


class NVIDIAScraper:
    __headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    __base_url = "https://www.nvidia.com/content/dam/en-zz/Solutions/product-security/product-security.json"

    def __init__(self, product_names: list):
        self.product_names = product_names
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def fetch_data(self, url: str) -> dict:
        try:
            async with self.session.get(url, headers=self.__headers) as response:
                if response.status == 200:
                    return await response.json()
                return {"error": f"Failed to fetch data. Status code: {response.status}"}
        except aiohttp.ClientError as e:
            return {"error": str(e)}

    async def scrape_nvidia_security(self) -> list:
        """
        Fetch and filter NVIDIA security bulletin entries matching the given product names.

        Returns:
            A list of matching security bulletin entries.
        """
        response = await self.fetch_data(self.__base_url)

        if "error" in response:
            return response["error"]

        bulletin_data = response.get("data", [])
        matching_entries = [
            entry
            for entry in bulletin_data
            if any(product.lower() in entry["title"].lower() for product in self.product_names)
        ]
        return matching_entries

    async def fetch_description_from_link(self, url: str) -> list | str:
        try:
            async with self.session.get(url, headers=self.__headers) as response:
                if response.status != 200:
                    return f"Failed to fetch description. Status code: {response.status}"

                soup = BeautifulSoup(await response.text(), "html.parser")
                table_tag = soup.select_one("figure.table")

                if not table_tag:
                    return "No table found on the page"

                tbody_tag = table_tag.find("tbody")
                if not tbody_tag:
                    return "No table body found on the page"

                rows = tbody_tag.find_all("tr")
                descriptions = [
                    {
                        "cve_id": cells[0].get_text(strip=True),
                        "description": cells[1].get_text(strip=True),
                    }
                    for row in rows
                    if (cells := row.find_all("td")) and len(cells) > 1
                ]
                return descriptions if descriptions else "No descriptions found in the table"
        except aiohttp.ClientError as e:
            return f"Error fetching description: {e}"

    async def extract_product_details(self, entries: list) -> list:
        """
        Extract the details of a particular product.

        Args:
            entries: A list of matched titles in the NVIDIA bulletin list.

        Returns:
            A list of the product details.
        """
        product_regex = r">(.+?)</a>"
        url_regex = r"https://nvidia.custhelp.com/app/answers/detail/a_id/\d+"

        structured_data = []

        for entry in entries:
            product_match = re.search(product_regex, entry["title"])
            product_name = product_match.group(1) if product_match else "Unknown"

            url_match = re.search(url_regex, entry["title"])
            url = url_match.group(0) if url_match else None

            descriptions = await self.fetch_description_from_link(url) if url else "No URL found"

            structured_data.append(
                {
                    "product_name": product_name,
                    "cve_id": entry.get("cve identifier(s)", "Unknown"),
                    "severity": entry.get("severity", "Unknown"),
                    "publish_date": entry.get("publish date", "Unknown"),
                    "last_updated": entry.get("last updated", "Unknown"),
                    "description": descriptions,
                    "link": url,
                }
            )
        return structured_data

    async def run_scraper(self) -> list:
        matching_entries = await self.scrape_nvidia_security()
        if isinstance(matching_entries, str):
            return [f"Error: {matching_entries}"]
        return await self.extract_product_details(matching_entries)


# Main execution
async def main():
    products = ["nemo", "chatrtx"]
    async with NVIDIAScraper(products) as scraper:
        product_details = await scraper.run_scraper()
        for detail in product_details:
            print(detail)


if __name__ == "__main__":
    asyncio.run(main())