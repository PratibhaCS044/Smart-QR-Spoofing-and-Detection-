from flask import Flask, request, render_template
import numpy as np
import pickle
import warnings
import os
import webbrowser
import threading

from feature import FeatureExtraction

warnings.filterwarnings("ignore")

# ============================================================
# 1. PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "pickle",
    "model.pkl"
)


# ============================================================
# 2. LOAD GRADIENT BOOSTING MODEL
# ============================================================

gbc = None

if os.path.exists(MODEL_PATH):

    try:
        with open(MODEL_PATH, "rb") as file:
            gbc = pickle.load(file)

        print("Model loaded successfully.")
        print("Model type:", type(gbc))
        print("Model path:", MODEL_PATH)

    except Exception as e:
        print("Error loading model:", e)

else:
    print("Model file not found at:", MODEL_PATH)


# ============================================================
# 3. CREATE FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# 4. DETECTION REASONS
# ============================================================

def get_detection_reasons(features):

    reasons = []

    feature_names = [

        "IP address",
        "Long URL",
        "Shortened URL",
        "@ symbol",
        "Redirecting //",
        "Prefix/Suffix -",
        "Subdomains",
        "HTTPS not used",
        "Domain registration",
        "Favicon",
        "Non-standard port",
        "HTTPS in domain",
        "External requests",
        "Anchor links",
        "Script links",
        "Server form handler",
        "Information email",
        "Abnormal URL",
        "Website forwarding",
        "Status bar customization",
        "Disabled right-click",
        "Popup window",
        "Iframe redirection",
        "Domain age",
        "DNS record",
        "Website traffic",
        "PageRank",
        "Google index",
        "Links pointing to page",
        "Suspicious indicators"
    ]


    short_reasons = {

        "IP address":
            "The URL uses an IP address instead of a normal domain",

        "Long URL":
            "The URL is unusually long",

        "Shortened URL":
            "The URL uses a shortened link",

        "@ symbol":
            "The URL contains an @ symbol",

        "Redirecting //":
            "The URL contains a suspicious redirection",

        "Prefix/Suffix -":
            "The domain contains a suspicious hyphen",

        "Subdomains":
            "The URL contains too many subdomains",

        "HTTPS not used":
            "HTTP is used instead of HTTPS",

        "Domain registration":
            "The domain registration looks suspicious",

        "Favicon":
            "The website uses an external favicon",

        "Non-standard port":
            "The website uses a non-standard port",

        "HTTPS in domain":
            "The domain contains the word HTTPS",

        "External requests":
            "The webpage makes many external requests",

        "Anchor links":
            "The webpage contains suspicious external links",

        "Script links":
            "The webpage contains many external script links",

        "Server form handler":
            "The website sends form data to an unusual location",

        "Information email":
            "The webpage contains a suspicious email indicator",

        "Abnormal URL":
            "The URL structure appears abnormal",

        "Website forwarding":
            "The website uses multiple redirects",

        "Status bar customization":
            "The website tries to modify the browser status bar",

        "Disabled right-click":
            "The website disables right-click",

        "Popup window":
            "The website uses suspicious popup windows",

        "Iframe redirection":
            "The website uses iframe redirection",

        "Domain age":
            "The domain appears to be newly registered",

        "DNS record":
            "The domain DNS information appears suspicious",

        "Website traffic":
            "The website has suspicious traffic information",

        "PageRank":
            "The website has a low or unavailable PageRank",

        "Google index":
            "The website is not indexed by Google",

        "Links pointing to page":
            "The page has unusual incoming links",

        "Suspicious indicators":
            "The website contains additional suspicious indicators"
    }


    # Check which features have suspicious value -1

    for name, value in zip(feature_names, features):

        if value == -1:
            reasons.append(short_reasons[name])


    return reasons


# ============================================================
# 5. MAIN URL / QR DETECTION
# ============================================================

@app.route("/", methods=["GET", "POST"])
def index():

    if request.method == "POST":

        # Get URL or QR content
        url = request.form.get("url", "").strip()


        # ----------------------------------------------------
        # Empty input
        # ----------------------------------------------------

        if not url:

            return render_template(
                "index.html",
                xx=-1,
                error="Please enter a valid URL or QR content."
            )


        try:

            # ------------------------------------------------
            # Feature extraction
            # ------------------------------------------------

            obj = FeatureExtraction(url)


            # ------------------------------------------------
            # Non-URL QR content
            # ------------------------------------------------

            if getattr(obj, "is_non_url", False):

                return render_template(
                    "index.html",
                    xx=-2,
                    url=url
                )


            # ------------------------------------------------
            # Check model
            # ------------------------------------------------

            if gbc is None:

                return render_template(
                    "index.html",
                    xx=-1,
                    url=url,
                    error="Classifier model is currently unavailable."
                )


            # ------------------------------------------------
            # Extract 30 features
            # ------------------------------------------------

            features = obj.getFeaturesList()


            if not features or len(features) != 30:

                return render_template(
                    "index.html",
                    xx=-1,
                    url=url,
                    error="Failed to extract 30 features from the URL."
                )


            print("\n===================================")
            print("URL:", url)
            print("Extracted Features:", features)
            print("Number of Features:", len(features))
            print("===================================")


            # ------------------------------------------------
            # Convert features into ML input
            # ------------------------------------------------

            x = np.array(features).reshape(1, 30)


            # ------------------------------------------------
            # Gradient Boosting prediction
            # ------------------------------------------------

            probability = float(
                gbc.predict_proba(x)[0, 1]
            )


            print("Prediction Probability:", probability)


            # ------------------------------------------------
            # Determine risk level
            # ------------------------------------------------

            if probability >= 0.70:

                risk_level = "SAFE"

            elif probability >= 0.40:

                risk_level = "SUSPICIOUS"

            else:

                risk_level = "UNSAFE"


            print("Risk Level:", risk_level)


            # ------------------------------------------------
            # Detection reasons
            # ------------------------------------------------

            reasons = get_detection_reasons(features)


            # ------------------------------------------------
            # Send result to HTML
            # ------------------------------------------------

            return render_template(

                "index.html",

                xx=round(probability, 2),

                url=url,

                reasons=reasons,

                risk_level=risk_level

            )


        except Exception as e:

            print("Error during prediction:", e)


            return render_template(

                "index.html",

                xx=-1,

                url=url,

                error=f"Analysis error: {str(e)}"

            )


    # ========================================================
    # GET REQUEST
    # ========================================================

    return render_template(
        "index.html",
        xx=-1
    )


# ============================================================
# 6. QR SPOOFING SIMULATION + ML DETECTION
# ============================================================

@app.route("/generate-spoof", methods=["POST"])
def generate_spoof():

    from spoofing.spoofing import generate_spoofed_qr


    # --------------------------------------------------------
    # Get original URL
    # --------------------------------------------------------

    original_url = request.form.get(
        "original_url",
        ""
    ).strip()


    # --------------------------------------------------------
    # Check empty URL
    # --------------------------------------------------------

    if not original_url:

        return render_template(

            "index.html",

            xx=-1,

            error="Please enter a URL for spoofing simulation."

        )


    try:

        # ====================================================
        # STEP 1: GENERATE SPOOFED URL + QR
        # ====================================================

        spoofed_url, qr_path = generate_spoofed_qr(
            original_url
        )


        print("\n===================================")
        print("QR SPOOFING SIMULATION")
        print("===================================")
        print("Original URL:", original_url)
        print("Spoofed URL:", spoofed_url)
        print("QR Path:", qr_path)


        # ====================================================
        # STEP 2: CHECK ML MODEL
        # ====================================================

        if gbc is None:

            return render_template(

                "index.html",

                xx=-1,

                spoofed_url=spoofed_url,

                spoofed_qr="/static/spoofed_qr/spoofed_qr.png",

                error="Classifier model is unavailable."

            )


        # ====================================================
        # STEP 3: FEATURE EXTRACTION
        # ====================================================

        obj = FeatureExtraction(
            spoofed_url
        )


        features = obj.getFeaturesList()


        print("Spoofed URL Features:", features)
        print("Number of Features:", len(features))


        # ====================================================
        # STEP 4: VERIFY 30 FEATURES
        # ====================================================

        if not features or len(features) != 30:

            return render_template(

                "index.html",

                xx=-1,

                spoofed_url=spoofed_url,

                spoofed_qr="/static/spoofed_qr/spoofed_qr.png",

                error="Could not extract 30 features from the spoofed URL."

            )


        # ====================================================
        # STEP 5: PREPARE ML INPUT
        # ====================================================

        x = np.array(
            features
        ).reshape(1, 30)


        # ====================================================
        # STEP 6: GRADIENT BOOSTING PREDICTION
        # ====================================================

        probability = float(

            gbc.predict_proba(x)[0, 1]

        )


        print("Spoofed URL Prediction Probability:", probability)


        # ====================================================
        # STEP 7: RISK CLASSIFICATION
        # ====================================================

        if probability >= 0.70:

            risk_level = "SAFE"

        elif probability >= 0.40:

            risk_level = "SUSPICIOUS"

        else:

            risk_level = "UNSAFE"


        print("Spoofed URL Risk Level:", risk_level)


        # ====================================================
        # STEP 8: GET DETECTION REASONS
        # ====================================================

        reasons = get_detection_reasons(
            features
        )


        # ====================================================
        # STEP 9: DISPLAY RESULT
        # ====================================================

        return render_template(

            "index.html",

            xx=round(probability, 2),

            url=spoofed_url,

            reasons=reasons,

            risk_level=risk_level,

            spoofed_url=spoofed_url,

            spoofed_qr="/static/spoofed_qr/spoofed_qr.png"

        )


    except Exception as e:

        print(
            "Spoofing detection error:",
            e
        )


        return render_template(

            "index.html",

            xx=-1,

            spoofed_url=(
                spoofed_url
                if "spoofed_url" in locals()
                else None
            ),

            spoofed_qr=(
                "/static/spoofed_qr/spoofed_qr.png"
                if "spoofed_url" in locals()
                else None
            ),

            error=f"Spoofing detection error: {str(e)}"

        )


# ============================================================
# 7. RUN FLASK APPLICATION
# ============================================================

if __name__ == "__main__":

    url = "http://127.0.0.1:8001"


    # Automatically open Chrome
    threading.Timer(

        1.5,

        lambda: webbrowser.open(url)

    ).start()


    # Start Flask server
    app.run(

        debug=True,

        port=8001

    )