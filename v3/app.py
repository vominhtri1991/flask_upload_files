from flask import Flask, request, render_template
import os
import magic  # Used to check MIME types
import binascii  # Used to verify file headers
from PIL import Image  # Used to open and verify images
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Secure upload folder
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Allowed file extensions
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Allowed MIME types (Ensuring file is actually an image)
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "image/gif"}

# Expected file headers (Magic Bytes)
FILE_MAGIC_BYTES = {
    "jpg": [b"\xFF\xD8\xFF\xE0", b"\xFF\xD8\xFF\xE1", b"\xFF\xD8\xFF\xDB"],
    "png": [b"\x89PNG\r\n\x1A\n"],
    "gif": [b"GIF87a", b"GIF89a"]
}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def check_file_mime(filepath):
    """Check MIME type using python-magic"""
    mime = magic.Magic(mime=True)
    file_mime_type = mime.from_file(filepath)
    return file_mime_type in ALLOWED_MIME_TYPES

def check_file_header(filepath):
    """Strictly validates the magic bytes to prevent polyglot attacks"""
    ext = filepath.rsplit(".", 1)[1].lower()

    if ext not in FILE_MAGIC_BYTES:
        return False  # Unknown file type

    with open(filepath, "rb") as f:
        file_header = f.read(8)  # Read first 8 bytes (sufficient for most types)

    return any(file_header.startswith(magic_bytes) for magic_bytes in FILE_MAGIC_BYTES[ext])

def verify_real_image(filepath):
    """Attempts to open the file as an image to detect non-image files"""
    try:
        with Image.open(filepath) as img:
            img.verify()  # Verifies the image file integrity
        return True
    except Exception:
        return False  # File is not a real image

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal and unwanted execution"""
    return secure_filename(filename)

@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if "file" not in request.files:
            return "No file part"

        file = request.files["file"]
        if file.filename == "":
            return "No selected file"

        # First check extension
        if not allowed_file(file.filename):
            return "❌ Invalid file extension!"

        # Sanitize filename
        filename = sanitize_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # Validate file MIME type using python-magic
        if not check_file_mime(filepath):
            os.remove(filepath)  # Delete unauthorized file
            return "❌ Invalid file content! Only images are allowed."

        # Validate file header (Magic Bytes)
        if not check_file_header(filepath):
            os.remove(filepath)  # Delete unauthorized file
            return "❌ File header mismatch! Possible polyglot attack detected."

        # Verify that the file is an actual image
        if not verify_real_image(filepath):
            os.remove(filepath)  # Delete unauthorized file
            return "❌ Uploaded file is not a valid image!"

        return f"✅ File uploaded successfully: {filepath}"

    return '''
    <!doctype html>
    <html>
        <head><title>Secure Image Upload</title></head>
        <body>
            <h2>Upload a Secure Image</h2>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="file" accept=".png,.jpg,.jpeg,.gif">
                <input type="submit" value="Upload">
            </form>
            <p>✅ This system prevents renamed extensions and polyglot attacks using file extension, MIME type, header validation, and real image verification!</p>
        </body>
    </html>
    '''

if __name__ == "__main__":
    app.run(debug=True)

