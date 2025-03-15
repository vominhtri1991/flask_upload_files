from flask import Flask, request, render_template
import os

app = Flask(__name__)

# Secure upload folder
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Allowed file extensions
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "txt", "pdf", "py"}

# Expected file headers (Magic Bytes) for common types
FILE_MAGIC_BYTES = {
    "jpg": [b"\xFF\xD8\xFF\xE0", b"\xFF\xD8\xFF\xE1", b"\xFF\xD8\xFF\xDB"],
    "png": [b"\x89PNG\r\n\x1A\n"],
    "gif": [b"GIF87a", b"GIF89a"],
    "pdf": [b"%PDF"],
    "py": [b"#!/usr/bin/python", b"#!/usr/bin/env python"]
}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def check_file_header(filepath):
    """Checks if file header (magic bytes) matches expected file type"""
    ext = filepath.rsplit(".", 1)[1].lower()
    
    if ext not in FILE_MAGIC_BYTES:
        return False  # Unknown file type

    with open(filepath, "rb") as f:
        file_header = f.read(8)  # Read first 8 bytes (sufficient for most types)

    return any(file_header.startswith(magic_bytes) for magic_bytes in FILE_MAGIC_BYTES[ext])

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

        # Save the file temporarily
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        # Validate file header (magic bytes)
        if not check_file_header(filepath):
            os.remove(filepath)  # Delete unauthorized file
            return "❌ File header mismatch! Possible polyglot attack detected."

        return f"✅ File uploaded successfully: {filepath}"

    return '''
    <!doctype html>
    <html>
        <head><title>Secure File Upload</title></head>
        <body>
            <h2>Upload a Secure File</h2>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="file" accept=".png,.jpg,.jpeg,.gif,.txt,.pdf,.py">
                <input type="submit" value="Upload">
            </form>
            <p>✅ Now with extension and header validation only!</p>
        </body>
    </html>
    '''

if __name__ == "__main__":
    app.run(debug=True)

