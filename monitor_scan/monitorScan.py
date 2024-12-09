from pymongo import MongoClient
from datetime import datetime
from hashlib import sha256
import asyncio
from scrapers.nvidia_scraper import NVIDIAScraper
# from scrapers.schneider import SchneiderScraper


class DatabaseConnection:
    """
    Manage database connection for the vulnerability scraper.
    :param: Database connection details
    """
    def __init__(self):
        # mongodb connection
        try:
            self.mongo_client = MongoClient("mongodb+srv://test:test123@cluster0.xqrer.mongodb.net/")
            self.db = self.mongo_client["monitor_scan"]
            self.users_collection = self.db["users"]
            self.user_products_collection = self.db["user_products"]
            self.vulnerabilities_collection = self.db["vulnerabilities"]
        except Exception as e:
            return f"MongoDB connection error: {e}"
        
    def initialize_collections(self):
        """Initialize collections with requiered indexes"""
        # For faster querying
        self.users_collection.create_index("email", unique=True)
        self.user_products_collection.create_index(
            ["user_id", "product_id"],
        )
        self.vulnerabilities_collection.create_index("cve_id", unique=True)

    def clear_collections(self):
        self.users_collection.delete_many({})
        self.user_products_collection.delete_many({})
        self.vulnerabilities_collection.delete_many({})
    
    def close_connections(self):
        self.mongo_client.close()
    


    def process_and_store_payload(self, payload: dict):
        try:
            user_id = payload.get("userId")
            user_email = payload.get("email")
            scan_data = payload.get("scanData")

            if not user_id or not user_email:
                raise ValueError("Invalid payload: userId and email are required.")

            # Upsert user data dynamically
            user_data = {"email": user_email, "updated_at": datetime.now()}
            self.users_collection.update_one(
                {"_id": user_id},
                {"$set": user_data},
                upsert=True
            )

            # Process scanData for incremental updates
            for scan_entry in scan_data:
                vendor_name = scan_entry.get("vendor")
                vendor_website = scan_entry.get("vendorWebsite")
                products = scan_entry.get("products")

                for product in products:
                    product_id = sha256(f"{product}_{user_id}".encode()).hexdigest()

                    # Fetch existing product document
                    existing_product = self.user_products_collection.find_one({"_id": product_id})
                    
                    # Prepare the update data
                    product_data = {
                        "vendor": vendor_name,
                        "vendor_website": vendor_website,
                        "product_name": product,
                        "updated_at": datetime.now(),
                    }

                    # Include only fields that are different or new
                    update_data = {
                        k: v for k, v in product_data.items()
                        if not existing_product or existing_product.get(k) != v
                    }

                    # If there are changes, update the document
                    if update_data:
                        self.user_products_collection.update_one(
                            {"_id": product_id},
                            {"$set": update_data, "$setOnInsert": {"user_id": user_id, "added_at": datetime.now()}},
                            upsert=True
                        )
            print(f"Processed payload for user: {user_email}")
        except Exception as e:
            print(f"Error processing payload: {e}")


class ScraperManager:
    def __init__(self, db_uri="mongodb+srv://test:test123@cluster0.xqrer.mongodb.net/", db_name="monitor_scan"):
        self.client = MongoClient(db_uri)
        self.db = self.client[db_name]


    async def fetch_user_products(self, user_ids):
        """
        Fetch products linked to multiple users, grouped by vendor for each user.
        
        :param user_ids: List of user IDs to fetch products for.
        :return: A dictionary where each key is a user_id and the value is their products grouped by vendor.
        """
        if not isinstance(user_ids, list):
            raise ValueError("user_ids must be a list of user ID strings.")

        # Fetch products for all user IDs in a single query
        user_products = list(
            self.db["user_products"].find({"user_id": {"$in": user_ids}})
        )
        if not user_products:
            print(f"No products found for users: {user_ids}")
            return {}

        products_by_user = {}
        # Group products by user and vendor
        for product in user_products:
            user_id = product.get("user_id")
            vendor = product.get("vendor")
            if user_id not in products_by_user:
                products_by_user[user_id] = {}
            if vendor not in products_by_user[user_id]:
                products_by_user[user_id][vendor] = []
            products_by_user[user_id][vendor].append(product.get("product_name"))
        
        return products_by_user

    def get_vendor_specific_product(self, products_by_user):
        vendor_products = {}

        for user_id, vendor_data in products_by_user.items():
            for vendor, products in vendor_data.items():
                if vendor not in vendor_products:
                    vendor_products[vendor] = set() # to avoid duplicates
                vendor_products[vendor].update(products)
        # convert sets back to lists for the final resulsts
        return {vendor: list(products) for vendor, products in vendor_products.items()}


class VendorScraperManager:
    def __init__(self):
        self.vendor_scrapers = {
            "NVIDIA": NVIDIAScraper,
        }

        self.db = DatabaseConnection()
    
    async def process_vendor(self, vendor, products):
        scraper_class = self.vendor_scrapers.get(vendor)
        if not scraper_class:
            print(f"No scraper class found for vendor: {vendor}")
            return
        # Instantiate the scraper class
        async with scraper_class(products) as scraper:
            print(f"Running scraper for vendor: {vendor}")
            details = await scraper.run_scraper()
            for detail in details:
                print(detail)
    
                vulnerability_data = {
                    "vendor": vendor,
                    "product_name": detail.get("product_name"),
                    "cve_id": detail.get("cve_id"),
                    "description": detail.get("description"),
                    "last_updated": detail.get("last_updated"),
                    "link": detail.get("link"),
                    "added_at": datetime.now(),
                }
                try:
                    # Insert the vulnerability if it doesn't already exist
                    self.db.vulnerabilities_collection.update_one(
                        {"cve_id": vulnerability_data["cve_id"]},
                        {"$set": vulnerability_data},
                        upsert=True
                    )
                    print(f"Vulnerability data saved: {vulnerability_data['cve_id']}")
                except Exception as e:
                    print(f"Error saving vulnerability data: {e}")
            
        
    async def process_all_vendors(self, vendor_products):
        tasks = []
        for vendor, products in vendor_products.items():
            tasks.append(self.process_vendor(vendor, products))
        
        # Run all vendor scraping tasks concurrently
        await asyncio.gather(*tasks)


async def main():
    payload = {
        "userId": "6752b04e67108c31580d4b53",
        "email": "chandanlokesh17@gmail.com",
        "scanData": [
            {"vendor": "Dell", "vendorWebsite": "https://www.dell.com", "products": ["Product AB", "one", "two"]},
            {"vendor": "Siemens","vendorWebsite": "https://www.siemens.com", "products": ["Product f"]},
            {"vendor": "GE","vendorWebsite": "https://www.ge.com", "products": ["Product 9", "Product 5100"]},
            {"vendor": "HP","vendorWebsite": "https://www.hp.com", "products": ["hp something"]}
        ]
    }

    payload1 = {
        "userId": "6752b04e67108c31580d4b5",
        "email": "chakraborty7117@gmail.com",
        "scanData": [
            {"vendor": "Dell", "vendorWebsite": "https://www.dell.com", "products": ["Product A", "one"]},
            {"vendor": "Siemens","vendorWebsite": "https://www.siemens.com", "products": ["Product f"]},
            {"vendor": "GE","vendorWebsite": "https://www.ge.com", "products": ["Product 9", "Product 5100"]},
            {"vendor": "HP","vendorWebsite": "https://www.hp.com", "products": ["hp something"]}
        ]
    }
    payload2 = {
        "userId": "6752b04e67108c31580d4b55",
        "email": "souvikc3030@gmail.com",
        "scanData": [
            {"vendor": "Dell", "vendorWebsite": "https://www.dell.com", "products": ["Product A", "one"]},
            {"vendor": "Siemens","vendorWebsite": "https://www.siemens.com", "products": ["Product f"]},
            {"vendor": "GE","vendorWebsite": "https://www.ge.com", "products": ["Product 9", "Product 5100"]},
            {"vendor": "HP","vendorWebsite": "https://www.hp.com", "products": ["hp something"]},
            {"vendor": "NVIDIA","vendorWebsite": "https://www.nvidia.com", "products": ["NeMo"]}
        ]
    }

    payload3 = {
        "userId": "6752b04e67108c31580d4b6",
        "email": "downeyjr0000@gmail.com",
        "scanData": [
            {"vendor": "Dell", "vendorWebsite": "https://www.dell.com", "products": ["Product A", "one"]},
            {"vendor": "NVIDIA","vendorWebsite": "https://www.nvidia.com", "products": ["NeMo", "ChatRTX", "GPU display driver"]}
        ]
    }

    # x = {'6752b04e67108c31580d4b6': {'NVIDIA': ['NeMo']}}
    # y = {'NVIDIA': ['nemo']}
    # z = y.get("NVIDIA")


    db = DatabaseConnection()
    # db.initialize_collections()
    # db.clear_collections()
    # db.process_and_store_payload(payload=payload)
    # db.process_and_store_payload(payload=payload1)
    # db.process_and_store_payload(payload=payload2)
    db.process_and_store_payload(payload=payload3)

    # print("Database connection done successfully")

    sp = ScraperManager()
    # data = asyncio.run(sp.fetch_user_products(["6752b04e67108c31580d4b53"]))
    # print(data)
    data = await sp.fetch_user_products(["6752b04e67108c31580d4b6"])
    print(data)
    vsp = sp.get_vendor_specific_product(data)
    print(vsp)
    

    # manager = VendorScraperManager()
    # vsm = await manager.process_all_vendors(z)
    # print(vsm)

    # vendor_products = {
    #     "NVIDIA": ["nemo", "chatrtx"],  # List of products for NVIDIA
    # }

    # Initialize the vendor scraper manager
    manager = VendorScraperManager()
    
    # Process all vendors concurrently
    await manager.process_all_vendors(vsp)
    

    db.close_connections()


if __name__ == "__main__":
    asyncio.run(main())