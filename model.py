import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score
import re
import joblib  # For saving and loading the model

# Feature extraction function
def extract_features_from_url(url):
    features = {}
    
    # URL Length
    features['length_url'] = len(url)
    
    # Number of dots in the hostname
    features['nb_dots'] = url.count('.')
    
    # Number of hyphens in the hostname
    features['nb_hyphens'] = url.count('-')
    
    # Number of '@' characters
    features['nb_at'] = url.count('@')
    
    # Number of '?' characters (query parameters)
    features['nb_qm'] = url.count('?')
    
    # Number of '&' characters (URL parameters)
    features['nb_and'] = url.count('&')
    
    # Number of '=' characters (URL key-value pairs)
    features['nb_eq'] = url.count('=')
    
    # Number of underscores in the path
    features['nb_underscore'] = url.count('_')
    
    # Length of the domain
    domain = re.findall(r'://([^/]+)', url)
    if domain:
        features['length_hostname'] = len(domain[0])
    else:
        features['length_hostname'] = 0
    
    # Extract subdomains (if any)
    subdomains = domain[0].split('.')[:-2]  # excluding TLD and domain
    features['nb_subdomains'] = len(subdomains)
    
    # Example of checking for "login" or "secure" keywords in the URL path
    features['contains_login'] = 1 if 'login' in url else 0
    features['contains_secure'] = 1 if 'secure' in url else 0
    
    return features

# Load dataset (assuming it's already cleaned and preprocessed)
data = pd.read_csv('phishing_urls.csv')

# Ensure that the target variable is numerical (0 for legitimate, 1 for phishing)
data['status'] = data['status'].map({'legitimate': 0, 'phishing': 1})

# Split the dataset into features and labels
X = data['url']  # URL column
y = data['status']  # Target column

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Feature extraction for training and testing sets
X_train_features = [extract_features_from_url(url) for url in X_train]
X_test_features = [extract_features_from_url(url) for url in X_test]

# Convert the list of features into DataFrame for both training and testing sets
X_train_df = pd.DataFrame(X_train_features)
X_test_df = pd.DataFrame(X_test_features)

# Initialize the RandomForest model
model = RandomForestClassifier(random_state=42)

# Hyperparameter tuning with GridSearchCV
param_grid = {
    'n_estimators': [100, 200],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1, 2]
}
grid_search = GridSearchCV(estimator=model, param_grid=param_grid, cv=3, n_jobs=-1, verbose=2)
grid_search.fit(X_train_df, y_train)

# Get the best model from grid search
best_model = grid_search.best_estimator_

# Train the best model
best_model.fit(X_train_df, y_train)

# Save the model
joblib.dump(best_model, 'model.pkl')

# Evaluate the model
y_pred = best_model.predict(X_test_df)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Test with additional URLs (expanded list)
new_urls = [
     "http://example.com/login.php",
    "http://malicious.com/steal_data",
    "https://secure-website.com",
    "https://www.genuinebank.com",
    "http://phishing-attack.com/fake-login",
    "https://www.real-shop.com/product?item=12345",
    "http://badlink.com/?redir=https://malicious-site.com",
    "http://www.fakebank.com/login.php",
    "https://www.trustworthy-shop.com/checkout",
    "http://malicious-attack.com/secure-payment",
    "http://secure-site.com/login",
    "http://bank-fake-site.com/account?session=1234",
    "https://www.real-shop.com/special-offer",
    "https://secure-login.example.com",
    "http://steal-data.com/collect",
    "https://www.google.com",
    "https://www.amazon.com",
    "https://www.paypal.com",
    "http://phishing-test.com",
    "http://scam-website.com/fake-login",
    "https://www.facebook.com",
    "http://dangerous-site.com/fake-offer",
    "http://example-mall.com",
    "https://www.twitter.com",
    "https://www.netflix.com",
    "http://malicious-site.com/secure-login",
    "https://legit-shop.com/order-confirmation",
    "http://fake-website.com/secure-payment",
    "http://fakedomain.com/payment-secure",
    "http://phishing-example.com/login",
    "https://real-site.com/contact-us",
    "http://www.untrustworthy.com/login",
    "http://securebank.com/fake-login",
    "https://www.linkedin.com",
    "http://fakeemail.com/confirm",
    "https://paypal-secure.com",
    "http://secure-transaction.com/payment",
    "https://www.target.com",
    "http://unsecure-site.com",
    "https://twitter-phishing.com/secure-login",
    "https://genuine-ecommerce-site.com/cart",
    "http://malicious-example.com/track",
    "http://www.abc.com/sign-in"
]

# Feature extraction for new URLs
new_url_features = [extract_features_from_url(url) for url in new_urls]

# Convert the list of features into a DataFrame
new_urls_df = pd.DataFrame(new_url_features)


# Make predictions on the new URLs
predictions = best_model.predict(new_urls_df)

# Display the results
for url, pred in zip(new_urls, predictions):
    status = 'legitimate' if pred == 0 else 'phishing'
    print(f"URL: {url}, Status: {status}")
