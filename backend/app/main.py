from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware  # Import CORSMiddleware
from .capture import (
    start_packet_capture,
    stop_packet_capture,
    get_capture_status,
    get_capture_summary,
    save_captured_packets,
    load_captured_packets,
    reset_capture,
)
import threading

app = FastAPI()

# Enable CORS for localhost:3000
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Add the frontend URL here
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Global variable to store the capture thread
capture_thread = None

@app.get("/start_capture")
def start_capture(filter: str = None):
    """Starts packet capture with an optional filter."""
    global capture_thread
    if capture_thread is None or not capture_thread.is_alive():
        capture_thread = threading.Thread(target=start_packet_capture, args=(filter,))
        capture_thread.start()
        return JSONResponse({"status": "Packet capture started"})
    else:
        return JSONResponse({"status": "Capture already running"}, status_code=400)

@app.get("/stop_capture")
def stop_capture():
    """Stops the packet capture."""
    if capture_thread and capture_thread.is_alive():
        stop_packet_capture()
        return JSONResponse({"status": "Packet capture stopped"})
    else:
        return JSONResponse({"status": "Capture is not running"}, status_code=400)

@app.get("/status")
def capture_status():
    """Returns the current capture status."""
    status = get_capture_status()
    return JSONResponse({"status": status})

@app.get("/summary")
def capture_summary():
    """Returns a summary of the captured packets."""
    summary = get_capture_summary()
    return JSONResponse({"summary": summary})

@app.post("/save_capture")
def save_capture(filename: str = "captured_packets.json"):
    """Saves captured packets to a specified file."""
    try:
        save_captured_packets(filename)
        return JSONResponse({"status": f"Captured packets saved to {filename}"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/load_capture")
def load_capture(filename: str = "captured_packets.json"):
    """Loads captured packets from a specified file."""
    try:
        packets = load_captured_packets(filename)
        if packets:
            return JSONResponse({"status": f"Packets loaded from {filename}", "packets": packets})
        else:
            return JSONResponse({"status": f"File {filename} not found or empty"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/reset_capture")
def reset_capture_endpoint():
    """Resets the capture data and statistics."""
    reset_capture()
    return JSONResponse({"status": "Capture reset successfully"})
