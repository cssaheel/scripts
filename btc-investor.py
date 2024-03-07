import yfinance as yf
import pandas as pd

# Set the investment details
investment_amount = 7000  # USD per month
start_date = '2023-01-01'  # Start of last year
end_date = '2024-01-01'  # End of last year
total_investment = 0

# Fetch historical data for Bitcoin
btc_data = yf.download('BTC-USD', start=start_date, end=end_date, interval='1mo')

# Calculate the number of Bitcoins purchased each month and update the total investment
btc_data['Investment'] = investment_amount / btc_data['Adj Close']
total_btc = btc_data['Investment'].sum()
total_investment = investment_amount * len(btc_data)

# Fetch the current price of Bitcoin
current_price = yf.download('BTC-USD', period='1d')['Adj Close'].iloc[-1]

# Calculate the current value of the Bitcoin balance
current_value = total_btc * current_price

print(f"Total Bitcoins acquired: {total_btc:.6f} BTC")
print(f"Total value paid: ${total_investment:.2f} USD")
print(f"Current value of BTC balance: ${current_value:.2f} USD")
