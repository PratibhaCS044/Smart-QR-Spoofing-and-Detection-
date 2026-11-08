import os
import qrcode

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "static",
    "spoofed_qr"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


def generate_spoofed_qr(original_url):

    original_url = original_url.strip()

    if not original_url:
        raise ValueError("URL cannot be empty.")

    # ---------------------------------------------------------
    # CONTROLLED SPOOFING TEST URL
    # ---------------------------------------------------------
    #
    # 192.0.2.123 is a reserved documentation/test IP address.
    # It is used here only for security simulation.
    #
    # The URL intentionally contains several characteristics
    # commonly associated with suspicious URLs:
    # - IP address
    # - HTTP instead of HTTPS
    # - non-standard port
    # - long URL
    # - hyphens
    # - extra redirection-style //
    # - @ symbol
    #
    # It is NOT a real phishing website.
    # ---------------------------------------------------------

    spoofed_url = (
        "http://192.0.2.123:8080/"
        "secure-login-account-verification/"
        "user@verify//login"
    )

    # ---------------------------------------------------------
    # CREATE QR CODE
    # ---------------------------------------------------------

    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4
    )

    qr.add_data(spoofed_url)

    qr.make(fit=True)

    img = qr.make_image()

    output_file = os.path.join(
        OUTPUT_DIR,
        "spoofed_qr.png"
    )

    img.save(output_file)

    return spoofed_url, output_file


# -------------------------------------------------------------
# TESTING DIRECTLY
# -------------------------------------------------------------

if __name__ == "__main__":

    print("=== QR Spoofing Simulation ===")

    original_url = input(
        "Enter the original URL for simulation: "
    ).strip()

    try:

        spoofed_url, output_file = generate_spoofed_qr(
            original_url
        )

        print("\nOriginal URL:")
        print(original_url)

        print("\nSimulated Spoofed URL:")
        print(spoofed_url)

        print("\nQR generated successfully!")

        print("Saved at:")
        print(output_file)

    except Exception as e:

        print("\nError:", e)