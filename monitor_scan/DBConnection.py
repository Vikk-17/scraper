from pymongo import MongoClient
from datetime import datetime
from hashlib import sha256



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
    


    def process_and_store_payload(self, payload:dict):
        # Add or update user
        try:
            user_id = payload.get("userId")
            user_email = payload.get("email")
            scan_data = payload.get("scanData")

            if not user_id or not user_email:
                raise ValueError("Invalid payload: userId and email are required.")

            user_data = {
                "_id": user_id,
                "email": user_email,
                "updated_at": datetime.now()
            }
            self.users_collection.update_one(
                {"_id": user_id},
                {"$set": user_data},
                upsert=True
            )

            # process scanData

            for scan_entry in scan_data:
                vendor_name = scan_entry.get("vendor")
                vendor_website = scan_entry.get("vendorWebsite")
                products = scan_entry.get("products")

                for product in products:
                    product_id = sha256(f"{product}_{user_id}".encode()).hexdigest()
                    product_data = {
                        "_id": product_id,
                        "user_id": user_id,
                        "vendor": vendor_name,
                        "vendor_website": vendor_website,
                        "product_name": product,
                        "added_at": datetime.now()
                    }

                    # insert or update product data
                    self.user_products_collection.update_one(
                        {"_id": product_id},
                        {"$set": product_data},
                        upsert=True
                    )
            print(f"Processed payload for user: {user_email}")
        except Exception as e:
            print(f"Error processing payload: {e}")

if __name__ == "__main__":
    
    payload = {
        "userId": "6752b04e67108c31580d4b53",
        "email": "chandanlokesh17@gmail.com",
        "scanData": [
            {"vendor": "Dell", "vendorWebsite": "https://www.dell.com", "products": ["Product A", "one"]},
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

    db = DatabaseConnection()
    db.initialize_collections()
    db.clear_collections()
    db.process_and_store_payload(payload=payload)
    db.process_and_store_payload(payload=payload1)
    db.process_and_store_payload(payload=payload2)

    print("Database connection done successfully")
    db.close_connections()


    """
    def process_and_store_payload(self, payload:dict):
        # Add or update user
        try:
            user_id = payload.get("userId")
            user_email = payload.get("email")
            scan_data = payload.get("scanData")

            if not user_id or not user_email:
                raise ValueError("Invalid payload: userId and email are required.")
            

            # check if the user already exists
            exisiting_user = self.users_collection.find_one({"_id": user_id})

            if exisiting_user and exisiting_user.get("email") == user_email:
                print(f"User {user_email} already exists.")
            else:
                user_data = {
                    "_id": user_id,
                    "email": user_email,
                    "updated_at": datetime.now()
                }
                self.users_collection.update_one(
                    {"_id": user_id},
                    {"$set": user_data},
                    upsert=True
                )

            # process scanData

            for scan_entry in scan_data:
                vendor_name = scan_entry.get("vendor")
                vendor_website = scan_entry.get("vendorWebsite")
                products = scan_entry.get("products")

                for product in products:
                    product_id = sha256(f"{product}_{user_id}".encode()).hexdigest()

                    exitsting_product = self.user_products_collection.find_one({"_id": product_id})
                    if exitsting_product:
                        print(f"Product {product} for user {user_email} already exists")
                    else:
                        product_data = {
                            "_id": product_id,
                            "user_id": user_id,
                            "vendor": vendor_name,
                            "vendor_website": vendor_website,
                            "product_name": product,
                            "added_at": datetime.now()
                        }

                        # insert or update product data
                        self.user_products_collection.update_one(
                            {"_id": product_id},
                            {"$set": product_data},
                            upsert=True
                        )
            print(f"Processed payload for user: {user_email}")
        except Exception as e:
            print(f"Error processing payload: {e}")
    """

        # async def fetch_user_products(self, user_id):
    #     """Fetch products linked to the user"""
    #     user_products = list(
    #         self.db["user_products"].find({"user_id": user_id})
    #     )
    #     if not user_products:
    #         print(f"No products found for user: {user_id}")
    #         return {}
        
    #     products_by_vendor = {}
    #     # Group products by vendor
    #     for product in user_products:
    #         vendor = product.get("vendor")
    #         if vendor not in products_by_vendor:
    #             products_by_vendor[vendor] = []
    #         products_by_vendor[vendor].append(product.get("product_name"))
    #     return products_by_vendor
    