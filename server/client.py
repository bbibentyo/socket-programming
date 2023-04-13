import requests


if __name__ == "__main__":
    url = "https://localhost:8443/"
    response = requests.get(url, verify="secrets/localhost_certificate.pem")
    print(response.text)
