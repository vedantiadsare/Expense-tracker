import google.generativeai as genai
import os

genai.configure(api_key="AIzaSyAJCBUsBaOQxW0uMW5J43Xs8RRfdr_jm5Y")
model = genai.GenerativeModel('learnlm-2.0-flash-experimental')

def analyze_transactions_csv(file_path):
    with open(file_path, "r") as f:
        csv_content = f.read()

    prompt = f"""
    Here's my monthly transaction data (CSV format):

    {csv_content}

    
        1. **Assume that I will continue to earn and spend the same way for the next few months.**
        2. **My monthly salary is ₹100,000. My total expenses this month were ₹294 (₹100 grooming + ₹194 toll).**
        3. This leaves me with a monthly surplus of ₹99,706.

        Please suggest a detailed investment plan tailored to this situation.

        **Be specific and include:**
        - Exact rupee amounts or percentages to invest in different instruments like Fixed Deposits (FDs), Systematic Investment Plans (SIPs), Mutual Funds (equity/debt), Direct Equity, etc.
        - Reasons for each investment choice based on surplus amount and low expenses.
        - A simple breakdown of how I can divide my monthly surplus for short-term stability, medium-term goals, and long-term wealth generation.
        - Consider that I am a moderate-risk investor who wants a balance between safety and returns.
        - Format the answer cleanly with headings, bullet points, and clear amounts.

        Only respond with the analysis and investment recommendation. Do not include disclaimers or general investment theory.
        """

    response = model.generate_content(prompt)
    return response.text
