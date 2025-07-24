from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import os
import uuid
import subprocess
import json

app = FastAPI()

# Allow CORS for all origins (adjust in production if needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Temporary directory for uploads
TEMP_DIR = "temp_uploads"
os.makedirs(TEMP_DIR, exist_ok=True)


@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """
    Uploads a .pcap or .pcapng file, analyzes it, and returns protocol statistics,
    IP conversations, and overall packet summary.
    """
    if not (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
        raise HTTPException(
            status_code=422,
            detail="Invalid file type. Please upload a .pcap or .pcapng file."
        )

    file_ext = '.pcapng' if file.filename.endswith('.pcapng') else '.pcap'
    temp_filename = os.path.join(TEMP_DIR, f"temp_{uuid.uuid4()}{file_ext}")

    try:
        with open(temp_filename, "wb") as f:
            f.write(await file.read())

        protocols = get_protocol_stats(temp_filename)
        ip_conversations = extract_ip_conversations(temp_filename)
        packet_summary = get_packet_summary(temp_filename)

        summary_path = temp_filename + ".summary.json"
        with open(summary_path, "w") as f:
            json.dump({
                "protocols": protocols,
                "ip_conversations": ip_conversations,
                "packet_summary": packet_summary
            }, f, indent=2)

        return {
            "protocols": protocols,
            "ip_conversations": ip_conversations,
            "packet_summary": packet_summary,
            "download_path": f"/download/{os.path.basename(summary_path)}"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")


@app.get("/download/{filename}")
def download_summary(filename: str):
    """
    Endpoint to download the generated JSON summary file.
    """
    path = os.path.join(TEMP_DIR, filename)
    if os.path.exists(path):
        return FileResponse(path, media_type="application/json", filename=filename)
    else:
        raise HTTPException(status_code=404, detail="File not found")


def get_protocol_stats(pcap_file: str):
    """
    Parses protocol statistics using tshark's 'io,phs' feature.
    Returns a list of protocols with packet and byte counts.
    """
    result = subprocess.run(
        ["tshark", "-r", pcap_file, "-q", "-z", "io,phs"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        raise Exception(f"TShark error: {result.stderr.strip()}")

    lines = result.stdout.splitlines()
    protocols = []
    inside_stats = False
    for line in lines:
        if "Protocol Hierarchy Statistics" in line:
            inside_stats = True
            continue
        if inside_stats:
            if line.strip() == "" or line.startswith("=") or "Filter:" in line:
                continue
            if "===" in line:
                break
            try:
                parts = line.strip().split()
                proto = parts[0]
                packets = int(parts[1].split(":")[1])
                bytes_ = int(parts[2].split(":")[1])
                protocols.append({"protocol": proto, "packets": packets, "bytes": bytes_})
            except:
                continue
    return protocols


def extract_ip_conversations(pcap_file: str):
    """
    Extracts IP conversations using tshark's 'conv,ip' statistics.
    Returns source/destination pairs with total byte count.
    """
    result = subprocess.run(
        ["tshark", "-r", pcap_file, "-q", "-z", "conv,ip"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        raise Exception(f"TShark convo error: {result.stderr.strip()}")

    lines = result.stdout.splitlines()
    conversations = []
    inside_section = False
    for line in lines:
        line = line.strip()
        if line.startswith("IPv4 Conversations"):
            inside_section = True
            continue
        if inside_section:
            if not line or line.startswith("=") or "Filter" in line:
                continue
            if "<->" not in line:
                continue
            try:
                parts = line.split("<->")
                if len(parts) != 2:
                    continue
                src = parts[0].strip().split()[0]
                rest = parts[1].strip().split()
                dst = rest[0]
                bytes_a_to_b = int(rest[2])
                bytes_b_to_a = int(rest[5])
                total_bytes = bytes_a_to_b + bytes_b_to_a
                conversations.append({
                    "source": src,
                    "destination": dst,
                    "bytes": total_bytes
                })
            except:
                continue
    return conversations


def get_packet_summary(pcap_file: str):
    """
    Gets a basic summary of total packets and total bytes using tshark 'io,stat,0'.
    """
    result = subprocess.run(
        ["tshark", "-r", pcap_file, "-q", "-z", "io,stat,0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if result.returncode != 0:
        raise Exception(f"TShark stats error: {result.stderr.strip()}")

    lines = result.stdout.splitlines()
    for line in lines:
        if line.strip().startswith("|") and "Frames" in line and "Bytes" in line:
            continue
        if line.strip().startswith("|"):
            try:
                parts = line.strip().split("|")
                packets = int(parts[2].strip())
                bytes_ = int(parts[3].strip())
                return {
                    "total_packets": packets,
                    "total_bytes": bytes_,
                }
            except:
                continue
    return {"total_packets": 0, "total_bytes": 0}
