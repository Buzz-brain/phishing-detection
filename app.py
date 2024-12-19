from flask import Flask, request, jsonify
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import re
import joblib  # For saving and loading the model


app = Flask(__name__)

# Load the pre-trained model (for example, use pickle to load your model)
model = RandomForestClassifier()
# model.load('model.pkl')  # Assuming the model is saved as model.pkl
# Load the model (this would be done in a different script or after the model has been saved)
model = joblib.load('model.pkl')

# Feature extraction function (same as before)
def extract_features_from_url(url):
    features = {}
    features['length_url'] = len(url)
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    domain = re.findall(r'://([^/]+)', url)
    if domain:
        features['length_hostname'] = len(domain[0])
    else:
        features['length_hostname'] = 0
    subdomains = domain[0].split('.')[:-2]
    features['nb_subdomains'] = len(subdomains)
    features['contains_login'] = 1 if 'login' in url else 0
    features['contains_secure'] = 1 if 'secure' in url else 0
    return features

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data['url']
    features = extract_features_from_url(url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)
    status = 'phishing' if prediction == 1 else 'legitimate'
    return jsonify({'url': url, 'status': status})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

