from fastapi import FastAPI, UploadFile, File, HTTPException
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
    if not (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
        raise HTTPException(
            status_code=422,
            detail="Invalid file type. Please upload a .pcap or .pcapng file."
        )

    file_ext = '.pcapng' if file.filename.endswith('.pcapng') else '.pcap'
    file_id = f"temp_{uuid.uuid4()}{file_ext}"
    temp_filename = os.path.join(TEMP_DIR, file_id)

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
            "file_id": file_id,  # <-- added this
            "protocols": protocols,
            "ip_conversations": ip_conversations,
            "packet_summary": packet_summary,
            "download_path": f"/download/{os.path.basename(summary_path)}"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Processing failed: {str(e)}")


@app.get("/download/{filename}")
def download_summary(filename: str):
    path = os.path.join(TEMP_DIR, filename)
    if os.path.exists(path):
        return FileResponse(path, media_type="application/json", filename=filename)
    else:
        raise HTTPException(status_code=404, detail="File not found")


@app.get("/packets/{file_id}")
def get_packet_details(file_id: str):
    """
    Parses individual packet details from a PCAP file using TShark.
    Returns basic packet-level data: number, time, src/dst IP & port, protocol, length.
    """
    file_path = os.path.join(TEMP_DIR, file_id)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="PCAP file not found.")

    try:
        # Correct: don't use -e with -T json
        tshark_fields = [
            "-T", "json",
            "-r", file_path,
            "-Y", "ip || tcp || udp"
        ]

        command = ["tshark"] + tshark_fields
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            raise Exception(f"TShark error: {result.stderr.strip()}")

        try:
            raw_packets = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise Exception(f"JSON Decode Error: {e.msg}")

        packets = []
        for pkt in raw_packets:
            layers = pkt.get("_source", {}).get("layers", {})
            packets.append({
                "no": int(layers.get("frame.number", ["0"])[0]),
                "time_ms": float(layers.get("frame.time_relative", ["0.0"])[0]),
                "src_ip": layers.get("ip.src", [""])[0] if "ip.src" in layers else layers.get("eth.src", [""])[0],
                "dst_ip": layers.get("ip.dst", [""])[0] if "ip.dst" in layers else layers.get("eth.dst", [""])[0],
                "src_port": layers.get("tcp.srcport", layers.get("udp.srcport", [""]))[0],
                "dst_port": layers.get("tcp.dstport", layers.get("udp.dstport", [""]))[0],
                "protocol": layers.get("_ws.col.Protocol", [""])[0],
                "length": layers.get("frame.len", [""])[0],
                "info": layers.get("_ws.col.Info", [""])[0],
            })

        return {"packets": packets}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to extract packets: {str(e)}")




def get_protocol_stats(pcap_file: str):
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
    result = subprocess.run(
        [
            "tshark", "-r", pcap_file,
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-E", "separator=,", "-E", "occurrence=f"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        raise Exception(f"TShark convo error: {result.stderr.strip()}")

    from collections import defaultdict
    conversations = defaultdict(int)  # key = (src, dst, proto), value = total bytes

    for line in result.stdout.strip().splitlines():
        parts = line.split(",")
        if len(parts) < 4:
            continue
        src, dst, proto, length = parts
        if not src or not dst or not proto:
            continue
        try:
            length = int(length)
        except ValueError:
            length = 0
        conversations[(src, dst, proto)] += length

    return [
        {"source": src, "destination": dst, "protocol": proto, "bytes": total_bytes}
        for (src, dst, proto), total_bytes in conversations.items()
    ]



def get_packet_summary(pcap_file: str):
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
