import asyncio
import aiohttp
import logging


products = ['NVIDIA', 'Microsoft Windows']

class VulnScraper:

    def setup_logging(self):
        """Create and configure logger """
        logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger("Product Vulnerability Scanner")

    async def monitor_nvd_for_products(self):
        """
        Monitor NVD feed for vuln in asyncronous manner
        """
        try:
            # Creates an ClientSession object as a connector
            # that can be connected to 100 different servers
            async with aiohttp.ClientSession() as session:
                # for each product creating the payload
                # user can provide either one or many products
                for product in products:
                    payload = {
                        "keywordSearch": product,
                    }
                    async with session.get(
                        url="https://services.nvd.nist.gov/rest/json/cves/2.0/",
                        params=payload,
                        headers={"apiKey": "key"},
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            return data
                        else:
                            return f"Error in fetching the data\n Status code: {response.status}"

        except Exception as e:
            self.logger.error(f"Error in NVD monitoring: {e}")

        # Graceful Shutdown
        # Zero-sleep to allow underlying connections to close
        # mainly ro a ClientSession without SSL
        # await asyncio.sleep(0)
        # with SSL connections, 300 s or 5 mins for the underlying
        # connections to close
        await asyncio.sleep(300)
