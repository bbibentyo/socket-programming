from fastapi import FastAPI


app = FastAPI()


@app.get("/")
def home():
    return {"message": "Hello World"}


if __name__ == "__main__":
    import uvicorn
    from pathlib import Path

    import secure

    secret_dir = Path(__file__).parent / "secrets"
    secret_dir.mkdir(exist_ok=True)

    ssl_keyfile_password = "very_insecure_PASSWORD_#321"
    ssl_keyfile = secret_dir / secure.private_key_filename
    ssl_certfile = secret_dir / secure.certificate_filename

    if not ssl_keyfile.exists():
        key, private_key_pem, public_key_pem = secure.generate_RSA_key_pair(ssl_keyfile_password)
        ssl_keyfile.write_bytes(private_key_pem)

        ssl_pubkeyfile = secret_dir / secure.public_key_filename
        ssl_pubkeyfile.write_bytes(public_key_pem)

        certificate = secure.generate_certificate(secure.generate_certificate_signing_request(key), key)
        secure.write_certificate_to_file(certificate, ssl_certfile)

        pkcs12 = secure.create_PKCS12_file("BossLocalhost", key, certificate, ssl_keyfile_password)
        ssl_pkcs12file = secret_dir / secure.pkcs12_filename
        ssl_pkcs12file.write_bytes(pkcs12)

    uvicorn.run(
        "main:app", host="0.0.0.0", port=8443,
        reload=True,
        ssl_keyfile=ssl_keyfile,
        ssl_certfile=ssl_certfile,
        ssl_keyfile_password=ssl_keyfile_password
    )
