import aiohttp
import asyncio
import re


class QuickScan:
    """
    Handles async requests and returns filtered data
    :params: takes product_name or cve_id
    :output: filterd list of cve_id with others details
    """
    
    # Dont't touch it
    __base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    __api_key = "api key"
    def __init__(self, product_name:str = None, product_version:str = None, product_cve:str = None):
        self.product_name = product_name
        self.product_version = product_version
        self.product_cve = product_cve
        
    @staticmethod
    async def fetch_data(session_name, url, params=None, headers=None):
        async with session_name.get(url, params=params, headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data
            else:
                return f"Error in fetching the data\n Status code: {response.status}"

    async def monitor_nvd_for_products(self):
        """
        Monitor NVD feed for vulnerbilities in asyncronous manner
        """
        try:
            # Creates an ClientSession object as a connector
            # that can be connected to 100 different servers
            async with aiohttp.ClientSession() as session:
                # for each product creating the payload
                # user can provide either one or many products
                # for product in products:


                # with the name of the product only
                if self.product_name:
                    payload = {
                        'keywordSearch': self.product_name,
                    }
                    raw_data = await self.fetch_data(session_name=session, url=self.__base_url, params=payload, headers={"apiKey": self.__api_key})
                    return raw_data
                
                # with the cve_id only
                elif self.product_cve :
                    payload = {
                        'cveId': self.product_cve,
                    }
                    raw_data = await self.fetch_data(session_name=session, url=self.__base_url, params=payload, headers={"apiKey": self.__api_key})
                    return raw_data
                
                # TODO: with both product_name and cve_id: bug
                # else:
                #     payload = {
                #         'cveId': self.product_cve,
                #         'keywordSearch': self.product_name,
                #     }
                #     raw_data = await self.fetch_data(session_name=session, url=self.__base_url, params=payload, headers={"apiKey": self.__api_key})
                #     return raw_data

        except Exception as e:
            return (f"Error in NVD monitoring: {e}")

        # Graceful Shutdown:
        # Zero-sleep to allow underlying connections to close
        # mainly ro a ClientSession without SSL
        # await asyncio.sleep(0)
        # with SSL connections, 300 s or 5 mins for the underlying
        # connections to close
        await asyncio.sleep(300)


    async def parse_formatted_data(self):
        """
        :params: takes raw data in json format
        :output: returns list of vulnerabilities 
        """
        
        baseScore_regex = r"'baseScore': (\d{1,2}\.?\d{1,2}?)"
        baseSeverity_regex = r"'baseSeverity': '([A-Z]*)'"
        url_regex = r"'url': '(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))',"
        
        product_details_dict = await self.monitor_nvd_for_products()
        
        if not product_details_dict or "vulnerabilities" not in product_details_dict:
            return "No vulnerabilities found or error in fetching data."

        vulnerabilities = product_details_dict.get("vulnerabilities", [])
        
        parsed_data_list = []
        for vuln in vulnerabilities:
            cve_path = vuln.get("cve", {})
            parsed_data = {
                "cve_id": cve_path.get("id", ""),
                "vulnerabilityDescription": cve_path.get("descriptions", [])[0]["value"].strip(),
                "published date": cve_path.get("published", ""),
                "last modified": cve_path.get("lastModified", ""),
                "vulnStatus": cve_path.get("vulnStatus", ""),
                

                "baseScore": re.search(baseScore_regex, str(vuln)).group(1),
                "baseSeverity": re.search(baseSeverity_regex, str(vuln)).group(1),
                "oemUrl": re.search(url_regex, str(vuln)).group(1)
                }
            parsed_data_list.append(parsed_data)
        # return parsed_data
        return parsed_data_list

