import google.generativeai as genai
import os

genai.configure(api_key="AIzaSyCiX0WbXfp4sMmQlme_f4t70tBxMp7CdNI")
model = genai.GenerativeModel("gemini-pro")

def analyze_transactions_csv(file_path):
    with open(file_path, "r") as f:
        csv_content = f.read()

    prompt = f"""
    Here's my monthly transaction data (CSV format):

    {csv_content}

    Assume I will earn the same salary and spend similarly next month.
    Based on this data, where can I realistically save money?
    Give practical suggestions by category.
    """

    response = model.generate_content(prompt)
    return response.text
