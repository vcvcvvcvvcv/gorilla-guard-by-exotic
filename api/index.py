import os, zipfile

root="/mnt/data/gtag_anticheat_hub"
os.makedirs(root+"/api", exist_ok=True)
os.makedirs(root+"/templates", exist_ok=True)
os.makedirs(root+"/static", exist_ok=True)

# Keep the existing project files if they were created above, but make the
# Vercel entrypoint explicit and compatible with Vercel's api/index.py detection.
api_index = '''from app import app

# Vercel looks for a top-level Flask WSGI application named "app".
'''
with open(root+"/api/index.py", "w", encoding="utf-8") as f:
    f.write(api_index)

# Also keep the legacy entrypoint so the project can still be run locally.
with open(root+"/vercel.py", "w", encoding="utf-8") as f:
    f.write("from app import app\n")

# Route all requests through the Vercel Python function.
vercel_json = '''{
  "version": 2,
  "builds": [
    {
      "src": "api/index.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "api/index.py"
    }
  ]
}
'''
with open(root+"/vercel.json", "w", encoding="utf-8") as f:
    f.write(vercel_json)

# Make sure the dependency file is present.
with open(root+"/requirements.txt", "w", encoding="utf-8") as f:
    f.write("Flask>=3.1,<4\n")

zip_path="/mnt/data/gorillaguard_anti_cheat_hub_FIXED.zip"
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for d, _, fs in os.walk(root):
        for name in fs:
            p=os.path.join(d, name)
            z.write(p, os.path.relpath(p, root))

print(f"Fixed project ZIP: {zip_path}")
print("Added: api/index.py")
print("Updated: vercel.json")
