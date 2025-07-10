from fastapi import FastAPI, UploadFile, File, HTTPException
import os
import uuid
import subprocess

app = FastAPI()

@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    # Validate file extension
    if not (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
        raise HTTPException(status_code=422, detail="Invalid file type. Please upload a .pcap or .pcapng file.")

    file_ext = '.pcapng' if file.filename.endswith('.pcapng') else '.pcap'
    temp_filename = f"temp_{uuid.uuid4()}{file_ext}"

    try:
        # Save uploaded file
        with open(temp_filename, "wb") as f:
            f.write(await file.read())

        # Use TShark to get protocol hierarchy summary
        result = subprocess.run(
            ["tshark", "-r", temp_filename, "-q", "-z", "io,phs"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            raise Exception(f"TShark error: {result.stderr.strip()}")

        # Parse TShark output into JSON format
        summary = result.stdout
        protocol_lines = extract_protocol_lines(summary)

        protocols = []
        for line in protocol_lines:
            try:
                parts = line.strip().split()
                proto = parts[0]
                frames = int(parts[1].split(":")[1])
                bytes_ = int(parts[2].split(":")[1])
                protocols.append({
                    "protocol": proto,
                    "frames": frames,
                    "bytes": bytes_
                })
            except Exception:
                continue

        return {
            "filename": file.filename,
            "total_protocols": len(protocols),
            "protocols": protocols
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")

    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

def extract_protocol_lines(output: str):
    lines = output.splitlines()
    extracted = []

    inside_stats = False
    for line in lines:
        # Start when the header appears
        if "Protocol Hierarchy Statistics" in line:
            inside_stats = True
            continue

        if inside_stats:
            # Skip empty or dashed lines
            if line.strip() == "" or line.startswith("=") or "Filter:" in line:
                continue
            # Break when a separator appears again (end of section)
            if "===" in line:
                break
            extracted.append(line.strip())
    return extracted
