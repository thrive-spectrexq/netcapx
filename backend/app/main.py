# backend/app/main.py
from fastapi import FastAPI
from .capture import start_packet_capture, stop_packet_capture, get_capture_status
from fastapi.responses import JSONResponse
import threading

app = FastAPI()

# Global variable to store the capture thread
capture_thread = None

@app.get("/start_capture")
def start_capture():
    global capture_thread
    if capture_thread is None or not capture_thread.is_alive():
        capture_thread = threading.Thread(target=start_packet_capture)
        capture_thread.start()
    return JSONResponse({"status": "Packet capture started"})

@app.get("/stop_capture")
def stop_capture():
    stop_packet_capture()
    return JSONResponse({"status": "Packet capture stopped"})

@app.get("/status")
def capture_status():
    status = get_capture_status()
    return JSONResponse({"status": status})
