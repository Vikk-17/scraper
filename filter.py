data = """{
  userId: '6752b04e67108c31580d4b53',
  productId: 'e6af77c6-1b43-4ab1-a403-f928c76b9a08',
  vendorName: 'Tech Solutions',
  productName: 'Firewall not pro'
}
{
  userId: '6752b04e67108c31580d4b53',
  productId: 'eedf45a3-7eab-4a9f-b000-67c82883b186',
  vendorName: 'Tech Solutions',
  productName: 'Firewall is not pro'
}
{
  userId: '6752b04e67108c31580d4b53',
  productId: 'eda402e7-1d07-4e45-ab8f-3a1bc636dfe7',
  vendorName: 'Hardware Systems Ltd.',
  productName: 'come product'
}"""



import json
import re
from collections import defaultdict


def payload_format(raw_data):
    
  data_cleaned = re.sub(r"(\w+): '([^']*)'", r'"\1": "\2"', raw_data)
  data_cleaned = f"[{data_cleaned.strip().replace('}\n{', '},\n{')}]"

  # Parse into a Python list
  data_list = json.loads(data_cleaned)


  main_payload = {
      "userId": data_list[0].get("userId"),
      "email": "", 
      "scanData": []
  }


  # group by vendor
  vendor_dict = defaultdict(dict)
  for item in data_list:
      vendor_dict[item.get("vendorName")][item["productName"]] = item["productId"]


  vendor_dict = dict(vendor_dict)

  # Building the scanData list
  for vendor, products in vendor_dict.items():
      main_payload["scanData"].append({
          "vendor": vendor,
          "products": products,
      })

  return main_payload


def main():
  print(payload_format(data))
   

if __name__ == "__main__":
   main()
