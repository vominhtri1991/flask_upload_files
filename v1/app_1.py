from flask import Flask, request, render_template
import os

app = Flask(__name__)

# Folder to store uploaded files
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Allowed file extensions (⚠️ Not secure alone)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "txt", "pdf"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if "file" not in request.files:
            return "No file part"

        file = request.files["file"]
        if file.filename == "":
            return "No selected file"

        # ⚠️ Only checking file extension (Vulnerable!)
        if not allowed_file(file.filename):
            return "❌ Invalid file type!"

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)
        return f"✅ File uploaded successfully: {filepath}"

    return '''
    <!doctype html>
    <html>
        <head><title>Upload File (Extension-Based Check)</title></head>
        <body>
            <h2>Upload a File</h2>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="file" accept=".png,.jpg,.jpeg,.gif,.txt,.pdf">
                <input type="submit" value="Upload">
            </form>
            <p>⚠️ This application only accept file .png,.jpg,.jpeg,.gif,.txt,.pdf!</p>
        </body>
    </html>
    '''

if __name__ == "__main__":
    app.run(debug=True)



